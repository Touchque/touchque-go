package touchque

import (
	"context"
	"encoding/json"
	"net/http"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// The headless step-up for a framework without an adapter: RunGuard,
// IsStatusPoll, the guard token (SignGuardToken / VerifyGuardToken) and
// NormalizeDetails, the same exports as the Node SDK's runGuard,
// isStatusPoll, signGuardToken, verifyGuardToken and normalizeDetails.

func TestGuardTokenSignAndVerify(t *testing.T) {
	claims := GuardTokenClaims{
		U: "jane@acme.com", A: "SEND_MONEY", D: DetailsDigest([]LoginDetail{{Label: "Amount", Value: "250 EUR"}}), R: "tx_1",
		St: string(StepWaiting), Rid: "req_1", N: "47", Cc: "K7P-2QX", Exp: time.Now().Add(time.Minute).UnixMilli(),
	}
	token := SignGuardToken("shh", claims)
	if !strings.HasPrefix(token, "v1.") || token != signGuardToken("shh", claims) {
		t.Fatalf("token = %q", token)
	}
	if got := VerifyGuardToken("shh", token); got == nil || !reflect.DeepEqual(*got, claims) {
		t.Fatalf("claims = %+v", got)
	}

	expired := claims
	expired.Exp = time.Now().Add(-time.Second).UnixMilli()
	other := strings.Split(SignGuardToken("shh", GuardTokenClaims{U: "mallory@acme.com", A: "SEND_MONEY", Exp: claims.Exp}), ".")
	parts := strings.Split(token, ".")
	for name, bad := range map[string]string{
		"another key":  SignGuardToken("other", claims),
		"expired":      SignGuardToken("shh", expired),
		"swapped body": parts[0] + "." + other[1] + "." + parts[2],
		"no mac":       parts[0] + "." + parts[1],
		"empty":        "",
	} {
		if VerifyGuardToken("shh", bad) != nil {
			t.Errorf("%s: verified", name)
		}
	}
}

func TestNormalizeDetails(t *testing.T) {
	if NormalizeDetails(nil) != nil || NormalizeDetails([]LoginDetail{}) != nil {
		t.Fatal("nil in, nil out")
	}
	got := NormalizeDetails([]LoginDetail{{Label: " Amount ", Value: "\t250 EUR\n"}, {Label: "To", Value: "Acme"}})
	if !reflect.DeepEqual(got, []LoginDetail{{Label: "Amount", Value: "250 EUR"}, {Label: "To", Value: "Acme"}}) {
		t.Fatalf("details = %+v", got)
	}
	if DetailsDigest(got) != DetailsDigest([]LoginDetail{{Label: "Amount ", Value: " 250 EUR"}, {Label: "To", Value: "Acme"}}) {
		t.Fatal("the digest a token binds must not see the spaces")
	}
}

func TestRunGuardAndIsStatusPoll(t *testing.T) {
	var status atomic.Value
	status.Store("PENDING")
	client, closeFn := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/login/request":
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"requestId": "req_1", "expiresAt": "t"})
		case r.Method == http.MethodGet && r.URL.Path == "/login/status/req_1":
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"status": status.Load()})
		case r.Method == http.MethodPost && r.URL.Path == "/login/req_1/consume":
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"consumed": true, "requestId": "req_1", "externalUsername": "jane@acme.com", "type": "LOGIN",
				"confirmedVia": "DEVICE", "assurance": map[string]interface{}{"phishingResistant": false, "method": "push"},
			})
		default:
			t.Errorf("unexpected %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	})
	defer closeFn()
	ctx := context.Background()

	if res := RunGuard(ctx, client, GuardInput{Action: "LOGIN"}); res.Status != 401 || res.Body.Error.Code != "unauthenticated" {
		t.Fatalf("no user: status=%d body=%+v", res.Status, res.Body)
	}

	first := RunGuard(ctx, client, GuardInput{User: "jane@acme.com", Action: "LOGIN"})
	if first.Status != 202 || first.Body.Touchque.State != StepWaiting || first.Body.Token == "" {
		t.Fatalf("first: status=%d body=%+v", first.Status, first.Body)
	}
	claims := VerifyGuardToken("shh", first.Body.Token)
	if claims == nil || claims.U != "jane@acme.com" || claims.A != "LOGIN" || claims.St != string(StepWaiting) || claims.Rid != "req_1" {
		t.Fatalf("claims = %+v", claims)
	}

	poll := GuardInput{User: "jane@acme.com", Action: "LOGIN", Token: first.Body.Token}
	if !IsStatusPoll(client, poll) {
		t.Fatal("a waiting token for the same user and action is a status poll")
	}
	for name, in := range map[string]GuardInput{
		"no token":       {User: "jane@acme.com", Action: "LOGIN"},
		"another user":   {User: "mallory@acme.com", Action: "LOGIN", Token: first.Body.Token},
		"another action": {User: "jane@acme.com", Action: "SEND_MONEY", Token: first.Body.Token},
		"other details":  {User: "jane@acme.com", Action: "LOGIN", Token: first.Body.Token, Details: []LoginDetail{{Label: "Amount", Value: "1"}}},
		"offline":        {User: "jane@acme.com", Action: "LOGIN", Token: first.Body.Token, Offline: true},
		"a typed code":   {User: "jane@acme.com", Action: "LOGIN", Token: first.Body.Token, Code: "ABCD123"},
		"a forged token": {User: "jane@acme.com", Action: "LOGIN", Token: SignGuardToken("other", *claims)},
	} {
		if IsStatusPoll(client, in) {
			t.Errorf("%s: counted as a status poll", name)
		}
	}

	if still := RunGuard(ctx, client, poll); still.Status != 202 || still.Body.Touchque.State != StepWaiting {
		t.Fatalf("still: status=%d body=%+v", still.Status, still.Body)
	}
	status.Store("CONFIRMED")
	done := RunGuard(ctx, client, poll)
	if done.Status != 200 || done.Approved == nil || done.Approved.RequestID != "req_1" || done.Approved.User != "jane@acme.com" || done.Approved.ConfirmedVia != "DEVICE" {
		t.Fatalf("done: status=%d approved=%+v", done.Status, done.Approved)
	}
}

func TestEnrollQRExpiry(t *testing.T) {
	if s := enrollQR("qr", nil, "2026-11-12T10:05:00.000Z", 1000); s.Enroll.ExpiresAt != "2026-11-12T10:05:00.000Z" {
		t.Fatalf("the API's own ISO 8601 expiresAt: %q", s.Enroll.ExpiresAt)
	}
	before := nowMs()
	s := enrollQR("qr", []string{"r1"}, "soon", 60000)
	if ms, ok := isoMs(s.Enroll.ExpiresAt); !ok || ms < before+60000 || ms > nowMs()+60000 || !strings.HasSuffix(s.Enroll.ExpiresAt, "Z") {
		t.Fatalf("now + ttlMs: %q", s.Enroll.ExpiresAt)
	}
	if s := enrollQR("qr", nil, "", 0); s.Enroll.ExpiresAt != "" {
		t.Fatalf("neither: %q", s.Enroll.ExpiresAt)
	}
	if ms, ok := isoMs("2026-11-12T12:05:00+02:00"); !ok || isoFromMs(ms) != "2026-11-12T10:05:00.000Z" {
		t.Fatalf("offset: %d %v", ms, ok)
	}
}

func TestRunGuardWithANilClientWithoutKeysIsMisconfigured(t *testing.T) {
	noKeys(t)
	if res := RunGuard(context.Background(), nil, GuardInput{User: "jane@acme.com", Action: "LOGIN"}); res.Status != 500 ||
		res.Body.Error.Code != "misconfigured" || res.Body.Touchque.Reason != "misconfigured" {
		t.Fatalf("status=%d body=%+v", res.Status, res.Body)
	}
	if res := RunGuard(context.Background(), nil, GuardInput{Action: "LOGIN"}); res.Status != 401 {
		t.Fatalf("no user: status=%d", res.Status)
	}
	if defaultClient.client.Load() != nil {
		t.Fatal("a failed build is not kept: the next call tries again")
	}
}

func TestIsStatusPollWithANilClientWithoutKeysIsFalse(t *testing.T) {
	noKeys(t)
	if IsStatusPoll(nil, GuardInput{User: "jane@acme.com", Action: "LOGIN", Token: "v1.e30.x"}) {
		t.Fatal("no client can be built: not a status poll")
	}
}

// A nil client is the default one, built from the environment once the keys are there, and shared
// by RunGuard, IsStatusPoll and Require.
func TestRunGuardWithANilClientUsesTheSharedDefaultClient(t *testing.T) {
	noKeys(t)
	api := startFakeAPI(t)
	api.link("jane@acme.com")
	ctx := context.Background()
	in := GuardInput{User: "jane@acme.com", Action: "SEND_MONEY", Details: []LoginDetail{{Label: "Amount", Value: "5 EUR"}}}
	if res := RunGuard(ctx, nil, in); res.Status != 500 {
		t.Fatalf("without keys: status=%d", res.Status)
	}

	withKeys(t, api)
	first := RunGuard(ctx, nil, in)
	if first.Status != 202 || first.Body.Touchque.State != StepWaiting {
		t.Fatalf("with keys: status=%d body=%+v", first.Status, first.Body)
	}
	built := defaultClient.client.Load()
	if built == nil {
		t.Fatal("the default client is kept once built")
	}
	poll := in
	poll.Token = first.Body.Token
	if !IsStatusPoll(nil, poll) {
		t.Fatal("IsStatusPoll(nil, …) verifies the token with the same default client")
	}

	// Require(nil, …) answers the poll with the same client and runs the handler once approved.
	api.approve("")
	if rec := serve(requireHandler(nil, "SEND_MONEY"), "jane@acme.com", first.Body.Token); rec.Code != 200 ||
		!strings.Contains(rec.Body.String(), `"done":true`) {
		t.Fatalf("Require(nil): status=%d body=%s", rec.Code, rec.Body.String())
	}
	if defaultClient.client.Load() != built {
		t.Fatal("Require(nil, …) and RunGuard(ctx, nil, …) share one default client")
	}
}

func TestTheDefaultClientIsBuiltOnceUnderConcurrentUse(t *testing.T) {
	noKeys(t)
	t.Setenv("TQ_API_KEY", "tq_test_key")
	t.Setenv("TQ_API_SECRET", "test_secret")
	got := make([]*Client, 32)
	var wg sync.WaitGroup
	for i := range got {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			got[i] = defaultClient.get(nil)
		}(i)
	}
	wg.Wait()
	for i, c := range got {
		if c == nil || c != got[0] {
			t.Fatalf("call %d got another client: %p, want %p", i, c, got[0])
		}
	}
}

// A status answer without expiresAt: the poll falls back to the token's Rx; a token without Rx (5.1)
// answers without expiresAt, as before.
func TestGuard_WithoutALiveExpiryPollsCarryRxAndA51TokenNone(t *testing.T) {
	c, closeFn := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/login/request":
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"requestId": "req_1", "expiresAt": "2030-01-01T00:00:30.000Z"})
		case r.Method == http.MethodGet && r.URL.Path == "/login/status/req_1":
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"status": "PENDING"}) // no expiresAt
		default:
			t.Errorf("unexpected %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	})
	defer closeFn()
	first := runGuard(c, GuardInput{User: "jane@acme.com", Action: "LOGIN"})
	poll := runGuard(c, GuardInput{User: "jane@acme.com", Action: "LOGIN", Token: first.Body.Token})
	if poll.Body.Touchque.State != StepWaiting || poll.Body.Touchque.ExpiresAt != "2030-01-01T00:00:30.000Z" ||
		VerifyGuardToken("shh", poll.Body.Token).Rx != VerifyGuardToken("shh", first.Body.Token).Rx {
		t.Fatalf("rx: %+v", poll.Body.Touchque)
	}
	claims := VerifyGuardToken("shh", first.Body.Token)
	claims.Rx = 0
	old := runGuard(c, GuardInput{User: "jane@acme.com", Action: "LOGIN", Token: SignGuardToken("shh", *claims)}) // a 5.1 token
	if old.Status != 202 || old.Body.Touchque.State != StepWaiting || old.Body.Touchque.ExpiresAt != "" ||
		VerifyGuardToken("shh", old.Body.Token).Rx != 0 {
		t.Fatalf("5.1 token: status=%d step=%+v", old.Status, old.Body.Touchque)
	}
}
