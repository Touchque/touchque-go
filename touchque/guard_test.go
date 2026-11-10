package touchque

import (
	"context"
	"encoding/json"
	"net/http"
	"reflect"
	"strings"
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
