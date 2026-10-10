package touchque

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// mountRelay mounts the relay handler under /touchque, the way partners do.
func mountRelay(c *Client, opts RelayOptions) http.Handler {
	if opts.UserID == nil {
		opts.UserID = func(*http.Request) string { return "user@example.com" }
	}
	mux := http.NewServeMux()
	mux.Handle("/touchque/", http.StripPrefix("/touchque", NewRelayHandler(c, opts)))
	return mux
}

// relayCall sends one request; body (when non-nil) is sent as JSON.
func relayCall(t *testing.T, h http.Handler, method, path string, body interface{}, mods ...func(*http.Request)) (*httptest.ResponseRecorder, map[string]interface{}) {
	t.Helper()
	var reader *bytes.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		reader = bytes.NewReader(b)
	} else {
		reader = bytes.NewReader(nil)
	}
	req := httptest.NewRequest(method, "/touchque"+path, reader)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	for _, m := range mods {
		m(req)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	var out map[string]interface{}
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	return rec, out
}

func fromAddr(addr string) func(*http.Request) {
	return func(r *http.Request) { r.RemoteAddr = addr }
}

func withHeader(k, v string) func(*http.Request) {
	return func(r *http.Request) { r.Header.Set(k, v) }
}

// silentClient fails the test if TouchQue is called at all.
func silentClient(t *testing.T) *Client {
	t.Helper()
	c, closeFn := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("TouchQue must not be called, got %s %s", r.Method, r.URL.Path)
		w.WriteHeader(500)
	})
	t.Cleanup(closeFn)
	return c
}

func callsTo(api *fakeAPI, path string) []map[string]interface{} {
	var out []map[string]interface{}
	for _, c := range api.calls() {
		if c["path"] == path {
			out = append(out, c)
		}
	}
	return out
}

type authRecorder struct {
	mu    sync.Mutex
	calls []AuthenticatedInfo
}

func (a *authRecorder) fn(w http.ResponseWriter, r *http.Request, info AuthenticatedInfo) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.calls = append(a.calls, info)
	http.SetCookie(w, &http.Cookie{Name: "sid", Value: "s-" + info.ExternalUsername})
	return nil
}

func (a *authRecorder) all() []AuthenticatedInfo {
	a.mu.Lock()
	defer a.mu.Unlock()
	return append([]AuthenticatedInfo(nil), a.calls...)
}

// ── Construction ──────────────────────────────────────────────────────

func TestRelay_PanicsWithoutUserID(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("NewRelayHandler without RelayOptions.UserID must panic")
		}
	}()
	NewRelayHandler(&Client{}, RelayOptions{})
}

// ── Auth-required routes ─────────────────────────────────────────────

func TestRelay_AuthRequiredRoutes401WithoutUser(t *testing.T) {
	h := mountRelay(silentClient(t), RelayOptions{UserID: func(*http.Request) string { return "" }})
	for _, rt := range []struct{ method, path string }{
		{"POST", "/enroll/start"},
		{"GET", "/enroll/status"},
		{"POST", "/passkey/register/options"},
		{"POST", "/passkey/register/verify"},
		{"GET", "/passkey/credentials"},
		{"DELETE", "/passkey/credentials/abc"},
	} {
		rec, out := relayCall(t, h, rt.method, rt.path, map[string]interface{}{})
		if rec.Code != 401 || out["error"] != "UNAUTHORIZED_FOR_2FA" {
			t.Fatalf("%s %s: expected 401 UNAUTHORIZED_FOR_2FA, got %d %v", rt.method, rt.path, rec.Code, out)
		}
	}
}

// ── Enrollment ───────────────────────────────────────────────────────

func TestRelay_EnrollStartNeverReplacesALinkedPhone(t *testing.T) {
	api := startFakeAPI(t)
	api.link("user@example.com")
	h := mountRelay(api.client(t), RelayOptions{})
	rec, out := relayCall(t, h, "POST", "/enroll/start", nil)
	if rec.Code != 409 || out["error"] != "already_linked" {
		t.Fatalf("expected 409 already_linked, got %d %v", rec.Code, out)
	}
	if n := len(callsTo(api, "/auth/secret/reset")); n != 0 {
		t.Fatalf("a linked phone must never be reset, got %d reset calls", n)
	}
}

func TestRelay_EnrollStartReissuesAnUnscannedQR(t *testing.T) {
	api := startFakeAPI(t)
	h := mountRelay(api.client(t), RelayOptions{})
	rec, out := relayCall(t, h, "POST", "/enroll/start", nil)
	if rec.Code != 200 || out["secret"] != "S" {
		t.Fatalf("expected the first secret, got %d %v", rec.Code, out)
	}
	rec, out = relayCall(t, h, "POST", "/enroll/start", nil)
	if rec.Code != 200 || out["secret"] != "S2" {
		t.Fatalf("expected a reset secret for a pending (unscanned) QR, got %d %v", rec.Code, out)
	}
}

func TestRelay_EnrollStatus(t *testing.T) {
	api := startFakeAPI(t)
	h := mountRelay(api.client(t), RelayOptions{})
	rec, out := relayCall(t, h, "GET", "/enroll/status", nil)
	if rec.Code != 200 || out["linked"] != false || out["used"] != false || out["deviceId"] != nil {
		t.Fatalf("unknown user should be {linked:false}, got %d %v", rec.Code, out)
	}
	api.link("user@example.com")
	_, out = relayCall(t, h, "GET", "/enroll/status", nil)
	if out["linked"] != true || out["used"] != true || out["deviceId"] != "dev-1" {
		t.Fatalf("expected linked, got %v", out)
	}
}

// ── Classic login (two-phase) ─────────────────────────────────────────

func TestRelay_LoginTwoPhaseFlow(t *testing.T) {
	api := startFakeAPI(t)
	api.link("user@example.com")
	api.opts(map[string]interface{}{"numberMatch": true})
	auth := &authRecorder{}
	h := mountRelay(api.client(t), RelayOptions{
		RateLimit:       &RateLimitOptions{Disabled: true},
		OnAuthenticated: auth.fn,
		Details: func(*http.Request) []LoginDetail {
			return []LoginDetail{{Label: "Action", Value: "Sign in"}}
		},
	})
	body := map[string]interface{}{"externalUsername": "user@example.com"}

	rec, first := relayCall(t, h, "POST", "/login", body, withHeader("User-Agent", "Mozilla/5.0 (Macintosh)"))
	if rec.Code != 202 {
		t.Fatalf("expected 202, got %d %s", rec.Code, rec.Body.String())
	}
	if rec.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("guard responses must be no-store, got %q", rec.Header().Get("Cache-Control"))
	}
	step := first["touchque"].(map[string]interface{})
	if step["state"] != "waiting" || step["number"] != "47" {
		t.Fatalf("unexpected step: %v", step)
	}
	sent := callsTo(api, "/login/request")
	if len(sent) != 1 {
		t.Fatalf("expected one push, got %d", len(sent))
	}
	sb := sent[0]["body"].(map[string]interface{})
	if sb["externalUsername"] != "user@example.com" || sb["type"] != "LOGIN" || sb["userAgent"] != "Mozilla/5.0 (Macintosh)" {
		t.Fatalf("unexpected push body: %v", sb)
	}
	if len(auth.all()) != 0 {
		t.Fatal("OnAuthenticated must not run before approval")
	}

	api.approve("")
	token := first["token"].(string)
	rec, done := relayCall(t, h, "POST", "/login", body, withHeader(GuardTokenHeader, token))
	if rec.Code != 200 || done["status"] != "success" || done["requestId"] != step["requestId"] {
		t.Fatalf("expected success, got %d %v", rec.Code, done)
	}
	if a, _ := done["assurance"].(map[string]interface{}); a == nil || a["method"] != "push" {
		t.Fatalf("expected push assurance, got %v", done["assurance"])
	}
	if !strings.Contains(rec.Header().Get("Set-Cookie"), "sid=s-user@example.com") {
		t.Fatalf("OnAuthenticated's cookie should be on the response, got %q", rec.Header().Get("Set-Cookie"))
	}
	calls := auth.all()
	if len(calls) != 1 || calls[0].ExternalUsername != "user@example.com" || calls[0].Via != ViaLogin || calls[0].RequestID != step["requestId"] {
		t.Fatalf("unexpected OnAuthenticated calls: %+v", calls)
	}

	rec, _ = relayCall(t, h, "POST", "/login", body, withHeader(GuardTokenHeader, token))
	if rec.Code == 200 {
		t.Fatal("a replayed token must not authenticate again")
	}
	if len(auth.all()) != 1 {
		t.Fatalf("OnAuthenticated must run exactly once, got %d", len(auth.all()))
	}
}

func TestRelay_LoginRequiresUsernameWithoutFirstFactor(t *testing.T) {
	h := mountRelay(silentClient(t), RelayOptions{})
	rec, out := relayCall(t, h, "POST", "/login", map[string]interface{}{})
	if rec.Code != 400 || out["error"] != "externalUsername_required" {
		t.Fatalf("expected 400, got %d %v", rec.Code, out)
	}
}

func TestRelay_LoginUnavailableIs503WithoutDetails(t *testing.T) {
	c := NewClient(&Config{APIKey: "tq_test_key", APISecret: "test_secret", BaseURL: "http://" + unusedLocalAddr(t), TimeoutMs: 2000})
	h := mountRelay(c, RelayOptions{})
	rec, out := relayCall(t, h, "POST", "/login", map[string]interface{}{"externalUsername": "user@example.com"})
	if rec.Code != 503 {
		t.Fatalf("expected 503, got %d %s", rec.Code, rec.Body.String())
	}
	if e, _ := out["error"].(map[string]interface{}); e == nil || e["code"] != "unavailable" {
		t.Fatalf("expected error.code unavailable, got %v", out)
	}
	if strings.Contains(rec.Body.String(), "127.0.0.1") {
		t.Fatal("internal network details must not reach the browser")
	}
}

// ── First-factor binding ──────────────────────────────────────────────

func TestRelay_LoginUserBindsLoginToTheFirstFactorUser(t *testing.T) {
	api := startFakeAPI(t)
	api.link("alice@example.com")
	h := mountRelay(api.client(t), RelayOptions{
		LoginUser: func(*http.Request) string { return "Alice@Example.com" },
		RateLimit: &RateLimitOptions{Disabled: true},
	})
	rec, _ := relayCall(t, h, "POST", "/login", map[string]interface{}{"externalUsername": "victim@example.com"})
	if rec.Code != 202 {
		t.Fatalf("expected 202, got %d %s", rec.Code, rec.Body.String())
	}
	pushes := callsTo(api, "/login/request")
	if len(pushes) != 1 || pushes[0]["body"].(map[string]interface{})["externalUsername"] != "alice@example.com" {
		t.Fatalf("expected exactly one push, to alice@example.com, got %v", pushes)
	}
}

func TestRelay_LoginUserEmptyIs401FirstFactorRequired(t *testing.T) {
	h := mountRelay(silentClient(t), RelayOptions{
		LoginUser: func(*http.Request) string { return "" },
		RateLimit: &RateLimitOptions{Disabled: true},
	})
	for _, path := range []string{"/login", "/offline/challenge", "/offline/totp"} {
		rec, out := relayCall(t, h, "POST", path, map[string]interface{}{"externalUsername": "victim@example.com", "code": "AAAAAAA"})
		if rec.Code != 401 || out["error"] != "FIRST_FACTOR_REQUIRED" {
			t.Fatalf("%s: expected 401 FIRST_FACTOR_REQUIRED, got %d %v", path, rec.Code, out)
		}
	}
}

// ── Offline sign ──────────────────────────────────────────────────────

func TestRelay_OfflineRoutesOffWithoutFirstFactor(t *testing.T) {
	h := mountRelay(silentClient(t), RelayOptions{RateLimit: &RateLimitOptions{Disabled: true}})
	for _, path := range []string{"/offline/challenge", "/offline/verify", "/offline/totp"} {
		rec, out := relayCall(t, h, "POST", path, map[string]interface{}{"externalUsername": "victim@example.com", "challengeId": "c1", "code": "AAAAAAA"})
		if rec.Code != 403 || out["error"] != "OFFLINE_REQUIRES_FIRST_FACTOR" {
			t.Fatalf("%s: expected 403 OFFLINE_REQUIRES_FIRST_FACTOR, got %d %v", path, rec.Code, out)
		}
	}
}

func TestRelay_OfflineVerifyUsesTouchQuesUser(t *testing.T) {
	api := startFakeAPI(t)
	auth := &authRecorder{}
	h := mountRelay(api.client(t), RelayOptions{AllowOfflineWithoutFirstFactor: true, OnAuthenticated: auth.fn})

	rec, ch := relayCall(t, h, "POST", "/offline/challenge", map[string]interface{}{"externalUsername": "Bob@Example.com"}, withHeader("User-Agent", "UA/1"))
	if rec.Code != 200 || ch["challengeId"] == nil || ch["totpAvailable"] != true {
		t.Fatalf("challenge failed: %d %v", rec.Code, ch)
	}
	sb := callsTo(api, "/offline/challenge")[0]["body"].(map[string]interface{})
	if sb["externalUsername"] != "bob@example.com" || sb["type"] != "LOGIN" || sb["userAgent"] != "UA/1" || sb["clientIp"] != "192.0.2.1" {
		t.Fatalf("unexpected challenge body: %v", sb)
	}

	rec, out := relayCall(t, h, "POST", "/offline/verify", map[string]interface{}{"challengeId": ch["challengeId"], "code": "WRONG00"})
	if rec.Code != 401 || out["reason"] != "invalid_code" || out["attemptsLeft"] != float64(4) {
		t.Fatalf("expected 401 invalid_code, got %d %v", rec.Code, out)
	}

	rec, out = relayCall(t, h, "POST", "/offline/verify", map[string]interface{}{"challengeId": ch["challengeId"], "code": "ABCD123", "externalUsername": "victim@example.com"})
	if rec.Code != 200 || out["status"] != "success" || out["approved"] != true || out["requestId"] != ch["challengeId"] {
		t.Fatalf("expected success, got %d %v", rec.Code, out)
	}
	calls := auth.all()
	if len(calls) != 1 || calls[0] != (AuthenticatedInfo{ExternalUsername: "bob@example.com", RequestID: ch["challengeId"].(string), Via: ViaOffline}) {
		t.Fatalf("unexpected OnAuthenticated calls: %+v", calls)
	}
}

func TestRelay_OfflineVerifyForAnotherUserOpensNoSession(t *testing.T) {
	api := startFakeAPI(t)
	c := api.client(t)
	unbound := mountRelay(c, RelayOptions{AllowOfflineWithoutFirstFactor: true})
	_, ch := relayCall(t, unbound, "POST", "/offline/challenge", map[string]interface{}{"externalUsername": "someone.else@example.com"})

	auth := &authRecorder{}
	bound := mountRelay(c, RelayOptions{LoginUser: func(*http.Request) string { return "alice@example.com" }, OnAuthenticated: auth.fn})
	rec, out := relayCall(t, bound, "POST", "/offline/verify", map[string]interface{}{"challengeId": ch["challengeId"], "code": "ABCD123"})
	if rec.Code != 401 || out["reason"] != "invalid_code" {
		t.Fatalf("expected 401, got %d %v", rec.Code, out)
	}
	if len(auth.all()) != 0 {
		t.Fatal("no session may be opened for another user's code")
	}
}

func TestRelay_OfflineTotp(t *testing.T) {
	api := startFakeAPI(t)
	auth := &authRecorder{}
	h := mountRelay(api.client(t), RelayOptions{AllowOfflineWithoutFirstFactor: true, OnAuthenticated: auth.fn})
	rec, out := relayCall(t, h, "POST", "/offline/totp", map[string]interface{}{"externalUsername": "User@Example.com", "code": "000000"})
	if rec.Code != 401 || out["reason"] != "invalid_code" {
		t.Fatalf("expected 401 invalid_code, got %d %v", rec.Code, out)
	}
	rec, out = relayCall(t, h, "POST", "/offline/totp", map[string]interface{}{"externalUsername": "User@Example.com", "code": "123456"})
	if rec.Code != 200 || out["approved"] != true {
		t.Fatalf("expected success, got %d %v", rec.Code, out)
	}
	sb := callsTo(api, "/offline/totp/verify")[1]["body"].(map[string]interface{})
	if sb["externalUsername"] != "user@example.com" || sb["type"] != "LOGIN" {
		t.Fatalf("unexpected totp body: %v", sb)
	}
	calls := auth.all()
	if len(calls) != 1 || calls[0] != (AuthenticatedInfo{ExternalUsername: "user@example.com", Via: ViaOfflineTotp}) {
		t.Fatalf("unexpected OnAuthenticated calls: %+v", calls)
	}
}

// ── Passkeys ──────────────────────────────────────────────────────────

func TestRelay_PasskeyLoginVerify(t *testing.T) {
	var mu sync.Mutex
	verifyResp := map[string]interface{}{}
	c, closeFn := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/webauthn/login/verify" {
			t.Errorf("unexpected path %s", r.URL.Path)
		}
		mu.Lock()
		defer mu.Unlock()
		_ = json.NewEncoder(w).Encode(verifyResp)
	})
	defer closeFn()
	setResp := func(m map[string]interface{}) { mu.Lock(); verifyResp = m; mu.Unlock() }
	body := map[string]interface{}{"requestId": "req_9", "response": map[string]interface{}{}, "externalUsername": "victim@example.com"}

	// With LoginUser, an approval for another user opens no session.
	setResp(map[string]interface{}{"success": true, "message": "ok", "externalUsername": "other@example.com", "requestId": "req_9"})
	auth := &authRecorder{}
	bound := mountRelay(c, RelayOptions{LoginUser: func(*http.Request) string { return "alice@example.com" }, OnAuthenticated: auth.fn})
	rec, out := relayCall(t, bound, "POST", "/passkey/login/verify", body)
	if rec.Code != 401 || out["error"] != "verification_failed" {
		t.Fatalf("expected 401 verification_failed, got %d %v", rec.Code, out)
	}
	if len(auth.all()) != 0 {
		t.Fatal("no session may be opened on a user mismatch")
	}

	// Without LoginUser, the session is for TouchQue's user, never the body's.
	unbound := mountRelay(c, RelayOptions{OnAuthenticated: auth.fn})
	rec, out = relayCall(t, unbound, "POST", "/passkey/login/verify", body)
	if rec.Code != 200 || out["success"] != true {
		t.Fatalf("expected 200, got %d %v", rec.Code, out)
	}
	calls := auth.all()
	if len(calls) != 1 || calls[0] != (AuthenticatedInfo{ExternalUsername: "other@example.com", RequestID: "req_9", Via: ViaPasskey}) {
		t.Fatalf("unexpected OnAuthenticated calls: %+v", calls)
	}

	// An older API that does not name the user: relayed, but no session.
	setResp(map[string]interface{}{"success": true, "message": "approved"})
	rec, _ = relayCall(t, unbound, "POST", "/passkey/login/verify", body)
	if rec.Code != 200 || len(auth.all()) != 1 {
		t.Fatalf("expected 200 and no new session, got %d, %d calls", rec.Code, len(auth.all()))
	}
}

func TestRelay_PasskeyPrimaryVerify(t *testing.T) {
	var mu sync.Mutex
	resp := map[string]interface{}{"success": true, "externalUsername": "user@example.com", "requestId": "req_2"}
	c, closeFn := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		_ = json.NewEncoder(w).Encode(resp)
	})
	defer closeFn()
	auth := &authRecorder{}
	h := mountRelay(c, RelayOptions{OnAuthenticated: auth.fn})

	rec, out := relayCall(t, h, "POST", "/passkey/authenticate/verify", map[string]interface{}{"attemptId": "att_1", "response": map[string]interface{}{}})
	if rec.Code != 200 || out["status"] != "success" || out["requestId"] != "req_2" {
		t.Fatalf("expected success, got %d %v", rec.Code, out)
	}
	if calls := auth.all(); len(calls) != 1 || calls[0] != (AuthenticatedInfo{ExternalUsername: "user@example.com", RequestID: "req_2", Via: ViaPasskey}) {
		t.Fatalf("unexpected OnAuthenticated calls: %+v", calls)
	}

	mu.Lock()
	resp = map[string]interface{}{"success": false, "requiresStepUp": true}
	mu.Unlock()
	rec, out = relayCall(t, h, "POST", "/passkey/authenticate/verify", map[string]interface{}{})
	if rec.Code != 200 || out["requiresStepUp"] != true || len(out) != 1 || len(auth.all()) != 1 {
		t.Fatalf("expected {requiresStepUp:true} without a session, got %d %v", rec.Code, out)
	}

	mu.Lock()
	resp = map[string]interface{}{"success": false}
	mu.Unlock()
	rec, out = relayCall(t, h, "POST", "/passkey/authenticate/verify", map[string]interface{}{})
	if rec.Code != 401 || out["error"] != "verification_failed" {
		t.Fatalf("expected 401, got %d %v", rec.Code, out)
	}
}

func TestRelay_PasskeyCredentials(t *testing.T) {
	api := startFakeAPI(t)
	h := mountRelay(api.client(t), RelayOptions{})
	rec, out := relayCall(t, h, "GET", "/passkey/credentials", nil)
	if rec.Code != 200 || out["credentials"] == nil {
		t.Fatalf("expected a credentials list, got %d %s", rec.Code, rec.Body.String())
	}
	rec, out = relayCall(t, h, "DELETE", "/passkey/credentials/cred_1", nil)
	if rec.Code != 200 || out["deleted"] != true {
		t.Fatalf("expected deleted, got %d %v", rec.Code, out)
	}
	del := callsTo(api, "/webauthn/credentials/cred_1")
	if len(del) != 1 || !strings.Contains(del[0]["url"].(string), "externalUsername=user%40example.com") {
		t.Fatalf("delete must be scoped to the signed-in user, got %v", del)
	}
}

// ── Error mapping ─────────────────────────────────────────────────────

func TestRelay_ClientErrorForwardsCodeOnly(t *testing.T) {
	c, closeFn := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(404)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"code": "no_passkey_registered", "error": "internal: row 42 missing", "message": "secret detail"})
	})
	defer closeFn()
	h := mountRelay(c, RelayOptions{})
	rec, out := relayCall(t, h, "POST", "/passkey/authenticate/options", map[string]interface{}{"email": "user@example.com"})
	if rec.Code != 404 || out["error"] != "no_passkey_registered" || len(out) != 1 {
		t.Fatalf("expected 404 {error: no_passkey_registered}, got %d %v", rec.Code, out)
	}
}

func TestRelay_ClientErrorFromFakeAPI(t *testing.T) {
	api := startFakeAPI(t)
	api.opts(map[string]interface{}{"offlineDisabled": true})
	h := mountRelay(api.client(t), RelayOptions{AllowOfflineWithoutFirstFactor: true})
	rec, out := relayCall(t, h, "POST", "/offline/challenge", map[string]interface{}{"externalUsername": "user@example.com"})
	if rec.Code != 403 || out["error"] != "offline_sign_disabled" || len(out) != 1 {
		t.Fatalf("expected 403 offline_sign_disabled, got %d %v", rec.Code, out)
	}
}

func TestRelay_ServerErrorIs502RelayError(t *testing.T) {
	c, closeFn := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(500)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"error": "db exploded"})
	})
	defer closeFn()
	h := mountRelay(c, RelayOptions{})
	rec, out := relayCall(t, h, "POST", "/passkey/login/options", map[string]interface{}{"requestId": "r1"})
	if rec.Code != 502 || out["error"] != "relay_error" || strings.Contains(rec.Body.String(), "exploded") {
		t.Fatalf("expected 502 relay_error, got %d %s", rec.Code, rec.Body.String())
	}

	offline := NewClient(&Config{APIKey: "tq_test_key", APISecret: "test_secret", BaseURL: "http://" + unusedLocalAddr(t), TimeoutMs: 2000})
	rec, out = relayCall(t, mountRelay(offline, RelayOptions{}), "GET", "/passkey/credentials", nil)
	if rec.Code != 502 || out["error"] != "relay_error" {
		t.Fatalf("a network failure should be 502 relay_error, got %d %v", rec.Code, out)
	}
}

func TestRelay_AuthResultErrorMapping(t *testing.T) {
	for _, tc := range []struct {
		err    error
		status int
		code   string
	}{
		{&RejectedError{Message: "x"}, 403, "2FA_REJECTED"},
		{&PasskeyRequiredError{RequestID: "r"}, 409, "PASSKEY_REQUIRED"},
		{&TimeoutError{Message: "x"}, 408, "2FA_TIMEOUT"},
		{&APIError{StatusCode: 404, Message: "m", Data: map[string]interface{}{"error": "device_not_linked"}}, 404, "device_not_linked"},
		{&APIError{StatusCode: 500, Message: "m"}, 503, "2FA_UNAVAILABLE"},
		{errors.New("boom"), 503, "2FA_UNAVAILABLE"},
	} {
		rec := httptest.NewRecorder()
		sendAuthResultError(rec, tc.err)
		var out map[string]interface{}
		_ = json.Unmarshal(rec.Body.Bytes(), &out)
		if rec.Code != tc.status || out["error"] != tc.code {
			t.Fatalf("%T: expected %d %s, got %d %v", tc.err, tc.status, tc.code, rec.Code, out)
		}
	}
}

func TestRelay_OnAuthenticatedErrorAbortsLogin(t *testing.T) {
	api := startFakeAPI(t)
	api.link("user@example.com")
	h := mountRelay(api.client(t), RelayOptions{
		OnAuthenticated: func(http.ResponseWriter, *http.Request, AuthenticatedInfo) error {
			return errors.New("session store down")
		},
	})
	body := map[string]interface{}{"externalUsername": "user@example.com"}
	_, first := relayCall(t, h, "POST", "/login", body)
	api.approve("")
	rec, out := relayCall(t, h, "POST", "/login", body, withHeader(GuardTokenHeader, first["token"].(string)))
	if rec.Code != 503 || out["error"] != "2FA_UNAVAILABLE" {
		t.Fatalf("expected 503, got %d %v", rec.Code, out)
	}
}

// ── Request bodies ────────────────────────────────────────────────────

func TestRelay_RequestBodies(t *testing.T) {
	h := mountRelay(silentClient(t), RelayOptions{})

	req := httptest.NewRequest("POST", "/touchque/login", strings.NewReader("{not json"))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != 400 {
		t.Fatalf("malformed JSON: expected 400, got %d", rec.Code)
	}

	big := `{"externalUsername":"` + strings.Repeat("a", relayMaxBodyBytes) + `"}`
	req = httptest.NewRequest("POST", "/touchque/login", strings.NewReader(big))
	req.Header.Set("Content-Type", "application/json")
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != 413 {
		t.Fatalf("oversized body: expected 413, got %d", rec.Code)
	}

	// A non-JSON content type (e.g. a cross-site form post) is never read.
	req = httptest.NewRequest("POST", "/touchque/login", strings.NewReader(`{"externalUsername":"victim@example.com"}`))
	req.Header.Set("Content-Type", "text/plain")
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != 400 || !strings.Contains(rec.Body.String(), "externalUsername_required") {
		t.Fatalf("text/plain body: expected 400 externalUsername_required, got %d %s", rec.Code, rec.Body.String())
	}
}

// ── Rate limiting ─────────────────────────────────────────────────────

func TestRelay_PushBombingCappedPerUserAcrossIPs(t *testing.T) {
	api := startFakeAPI(t)
	api.link("victim@example.com")
	h := mountRelay(api.client(t), RelayOptions{RateLimit: &RateLimitOptions{PerUser: 3, PerIP: 100}})
	var statuses []int
	for i := 0; i < 5; i++ {
		rec, out := relayCall(t, h, "POST", "/login", map[string]interface{}{"externalUsername": "victim@example.com"}, fromAddr(fmt.Sprintf("198.51.100.%d:4000", i)))
		statuses = append(statuses, rec.Code)
		if rec.Code == 429 {
			ra, _ := strconv.Atoi(rec.Header().Get("Retry-After"))
			if ra <= 0 || out["error"] != "RATE_LIMITED" || out["retryAfter"] != float64(ra) {
				t.Fatalf("429 needs Retry-After and RATE_LIMITED, got %q %v", rec.Header().Get("Retry-After"), out)
			}
		}
	}
	if fmt.Sprint(statuses) != "[202 202 202 429 429]" {
		t.Fatalf("unexpected statuses %v", statuses)
	}
	if n := len(callsTo(api, "/login/request")); n != 3 {
		t.Fatalf("the limiter should have stopped the rest, got %d pushes", n)
	}
}

func TestRelay_UsernameSprayCappedPerIP(t *testing.T) {
	api := startFakeAPI(t)
	h := mountRelay(api.client(t), RelayOptions{AllowOfflineWithoutFirstFactor: true, RateLimit: &RateLimitOptions{PerIP: 4, PerUser: 100}})
	limited := 0
	for i := 0; i < 6; i++ {
		// Same host, a new source port per request (a new connection): still one IP.
		rec, _ := relayCall(t, h, "POST", "/offline/challenge", map[string]interface{}{"externalUsername": fmt.Sprintf("u%d@example.com", i)}, fromAddr(fmt.Sprintf("203.0.113.7:%d", 50000+i)))
		if rec.Code == 429 {
			limited++
		}
	}
	if limited != 2 {
		t.Fatalf("expected 2 limited requests, got %d", limited)
	}
	if n := len(callsTo(api, "/offline/challenge")); n != 4 {
		t.Fatalf("expected 4 challenges to reach TouchQue, got %d", n)
	}
}

func TestRelay_RateLimitDisabled(t *testing.T) {
	api := startFakeAPI(t)
	api.link("a@example.com")
	h := mountRelay(api.client(t), RelayOptions{RateLimit: &RateLimitOptions{Disabled: true}})
	for i := 0; i < 30; i++ {
		if rec, _ := relayCall(t, h, "POST", "/login", map[string]interface{}{"externalUsername": "a@example.com"}); rec.Code != 202 {
			t.Fatalf("request %d: expected 202, got %d", i, rec.Code)
		}
	}
}

func TestRelay_ConcurrentRequestsShareOneLimit(t *testing.T) {
	c, closeFn := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"challenge": "c"})
	})
	defer closeFn()
	h := mountRelay(c, RelayOptions{RateLimit: &RateLimitOptions{PerIP: 10}})
	var ok, limited int64
	var wg sync.WaitGroup
	for i := 0; i < 40; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			rec, _ := relayCall(t, h, "POST", "/passkey/login/options", map[string]interface{}{"requestId": "r"}, fromAddr(fmt.Sprintf("203.0.113.9:%d", 40000+i)))
			switch rec.Code {
			case 200:
				atomic.AddInt64(&ok, 1)
			case 429:
				atomic.AddInt64(&limited, 1)
			}
		}(i)
	}
	wg.Wait()
	if ok != 10 || limited != 30 {
		t.Fatalf("expected 10 allowed / 30 limited, got %d / %d", ok, limited)
	}
}

// ── Limiter ───────────────────────────────────────────────────────────

func TestLimiter_DefaultsAndWindow(t *testing.T) {
	l := newFixedWindowLimiter(RateLimitOptions{})
	if l.window != 60*time.Second || l.perIP != 20 || l.perUser != 5 {
		t.Fatalf("unexpected defaults: %v %d %d", l.window, l.perIP, l.perUser)
	}
	now := time.Unix(1_000, 0)
	l.now = func() time.Time { return now }
	if l.hit("k", 2) != 0 || l.hit("k", 2) != 0 {
		t.Fatal("first two hits should pass")
	}
	if w := l.hit("k", 2); w != 60 {
		t.Fatalf("expected a 60 s wait, got %d", w)
	}
	now = now.Add(59500 * time.Millisecond)
	if w := l.hit("k", 2); w != 1 {
		t.Fatalf("expected the wait rounded up to 1 s, got %d", w)
	}
	now = now.Add(500 * time.Millisecond)
	if w := l.hit("k", 2); w != 0 {
		t.Fatalf("a new window should pass, got %d", w)
	}
}

func TestLimiter_KeyMapIsBounded(t *testing.T) {
	l := newFixedWindowLimiter(RateLimitOptions{})
	l.maxKeys = 10
	base := time.Unix(1_000, 0)
	i := 0
	l.now = func() time.Time { return base.Add(time.Duration(i) * time.Millisecond) }
	for ; i < 100; i++ {
		l.hit(fmt.Sprintf("k%d", i), 5)
		if len(l.entries) > l.maxKeys {
			t.Fatalf("key map grew to %d", len(l.entries))
		}
	}
	if _, ok := l.entries["k99"]; !ok {
		t.Fatal("the newest key must survive pruning")
	}
}

func TestLimiter_ConcurrentHits(t *testing.T) {
	l := newFixedWindowLimiter(RateLimitOptions{})
	var allowed int64
	var wg sync.WaitGroup
	for g := 0; g < 64; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < 50; i++ {
				if l.hit("shared", 1000) == 0 {
					atomic.AddInt64(&allowed, 1)
				}
				l.hit(fmt.Sprintf("own-%d", g), 1000)
			}
		}(g)
	}
	wg.Wait()
	if allowed != 1000 {
		t.Fatalf("expected exactly 1000 allowed hits, got %d", allowed)
	}
}
