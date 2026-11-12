package touchque

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func requireHandler(c *Client, action string) http.Handler {
	protected := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		approval, _ := ApprovalFromContext(r.Context())
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"done": true, "touchque": approval})
	})
	return Require(c, action, protected, RequireOptions{
		User: func(r *http.Request) string { return r.Header.Get("X-User") },
		Details: func(r *http.Request) []LoginDetail {
			return []LoginDetail{{Label: "Amount", Value: "5 EUR"}}
		},
	})
}

func TestRequire_FullFlow(t *testing.T) {
	api := startFakeAPI(t)
	api.link("jane@acme.com")
	api.opts(map[string]interface{}{"numberMatch": true})
	c := api.client(t)
	handler := requireHandler(c, "SEND_MONEY")

	req1 := httptest.NewRequest(http.MethodPost, "/transfer", nil)
	req1.Header.Set("X-User", "jane@acme.com")
	rec1 := httptest.NewRecorder()
	handler.ServeHTTP(rec1, req1)
	if rec1.Code != 202 {
		t.Fatalf("expected 202, got %d: %s", rec1.Code, rec1.Body.String())
	}
	var first struct {
		Touchque Step   `json:"touchque"`
		Token    string `json:"token"`
	}
	if err := json.Unmarshal(rec1.Body.Bytes(), &first); err != nil {
		t.Fatalf("bad json: %v", err)
	}
	if first.Touchque.Number != "47" {
		t.Fatalf("expected number matching digits, got %+v", first.Touchque)
	}

	api.approve("")
	req2 := httptest.NewRequest(http.MethodPost, "/transfer", nil)
	req2.Header.Set("X-User", "jane@acme.com")
	req2.Header.Set(GuardTokenHeader, first.Token)
	rec2 := httptest.NewRecorder()
	handler.ServeHTTP(rec2, req2)
	if rec2.Code != 200 {
		t.Fatalf("expected 200, got %d: %s", rec2.Code, rec2.Body.String())
	}
	var done struct {
		Done bool `json:"done"`
	}
	_ = json.Unmarshal(rec2.Body.Bytes(), &done)
	if !done.Done {
		t.Fatal("expected the protected handler to have run")
	}

	// Replaying the same token must not run the handler again.
	req3 := httptest.NewRequest(http.MethodPost, "/transfer", nil)
	req3.Header.Set("X-User", "jane@acme.com")
	req3.Header.Set(GuardTokenHeader, first.Token)
	rec3 := httptest.NewRecorder()
	handler.ServeHTTP(rec3, req3)
	if rec3.Code == 200 {
		t.Fatal("expected the replayed token to be refused")
	}
}

func TestRequire_NoUserIs401(t *testing.T) {
	api := startFakeAPI(t)
	c := api.client(t)
	handler := requireHandler(c, "SEND_MONEY")

	req := httptest.NewRequest(http.MethodPost, "/transfer", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != 401 {
		t.Fatalf("expected 401, got %d", rec.Code)
	}
}

func TestRequire_PanicsWithoutUserResolver(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("Require without RequireOptions.User must panic")
		}
	}()
	Require(&Client{}, "SEND_MONEY", http.NotFoundHandler(), RequireOptions{})
}

func TestRequire_IgnoresClientSuppliedUserHeader(t *testing.T) {
	api := startFakeAPI(t)
	api.link("victim@acme.com")
	c := api.client(t)
	handler := Require(c, "SEND_MONEY", http.NotFoundHandler(), RequireOptions{
		User: func(r *http.Request) string { return "" }, // nobody signed in
	})
	req := httptest.NewRequest(http.MethodPost, "/transfer", nil)
	req.Header.Set("X-Touchque-User", "victim@acme.com")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != 401 {
		t.Fatalf("expected 401 for an anonymous request, got %d: %s", rec.Code, rec.Body.String())
	}
}

// R1-01: the API needs an address, not "ip:port" — with the port it fell
// back to scoring the partner's server.
func TestRequire_SendsHostOnlyClientIP(t *testing.T) {
	api := startFakeAPI(t)
	api.link("jane@acme.com")
	c := api.client(t)
	handler := requireHandler(c, "SEND_MONEY")

	for _, remote := range []string{"192.0.2.1:1234", "[2001:db8::1]:443"} {
		req := httptest.NewRequest(http.MethodPost, "/transfer", nil)
		req.RemoteAddr = remote
		req.Header.Set("X-User", "jane@acme.com")
		handler.ServeHTTP(httptest.NewRecorder(), req)
	}
	var got []interface{}
	for _, call := range api.calls() {
		if call["path"] == "/login/request" {
			body, _ := call["body"].(map[string]interface{})
			got = append(got, body["clientIp"])
		}
	}
	if len(got) != 2 || got[0] != "192.0.2.1" || got[1] != "2001:db8::1" {
		t.Fatalf("clientIp sent: %v", got)
	}
}

func TestHostOnly(t *testing.T) {
	for in, want := range map[string]string{"192.0.2.1:80": "192.0.2.1", "[::1]:80": "::1", "192.0.2.1": "192.0.2.1", "2001:db8::1": "2001:db8::1"} {
		if got := hostOnly(in); got != want {
			t.Errorf("hostOnly(%q) = %q, want %q", in, got, want)
		}
	}
}

// ── no keys: a JSON answer, never a panic ────────────────────────────────

// noKeys: TQ_API_KEY / TQ_API_SECRET unset, and the "not set" line not logged yet in this process.
func noKeys(t *testing.T) {
	t.Helper()
	t.Setenv("TQ_API_KEY", "")
	t.Setenv("TQ_API_SECRET", "")
	t.Setenv("TQ_API_URL", "")
	warnedUnconfigured.Store(false)
	t.Cleanup(func() { warnedUnconfigured.Store(false) })
}

func serve(h http.Handler, user, token string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, "/transfer", nil)
	if user != "" {
		req.Header.Set("X-User", user)
	}
	if token != "" {
		req.Header.Set(GuardTokenHeader, token)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

const misconfiguredJSON = `{"touchque":{"state":"blocked","reason":"misconfigured"},` +
	`"error":{"code":"misconfigured","message":"Two-factor approval is not configured correctly."}}`

func TestRequire_NilClientWithoutKeysAnswers500Misconfigured(t *testing.T) {
	noKeys(t)
	var buf bytes.Buffer
	ran := 0
	protected := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { ran++ })
	handler := Require(nil, "SEND_MONEY", protected, RequireOptions{ // nothing panics at wiring time
		User:   func(r *http.Request) string { return r.Header.Get("X-User") },
		Logger: slog.New(slog.NewTextHandler(&buf, nil)),
	})
	for i := 0; i < 2; i++ {
		rec := serve(handler, "jane@acme.com", "")
		if rec.Code != 500 || strings.TrimSpace(rec.Body.String()) != misconfiguredJSON ||
			rec.Header().Get("Cache-Control") != "no-store" || rec.Header().Get("Content-Type") != "application/json" {
			t.Fatalf("status=%d headers=%v body=%s", rec.Code, rec.Header(), rec.Body.String())
		}
	}
	if rec := serve(handler, "", ""); rec.Code != 401 || !strings.Contains(rec.Body.String(), `"code":"unauthenticated"`) {
		t.Fatalf("anonymous: status=%d body=%s", rec.Code, rec.Body.String())
	}
	if ran != 0 {
		t.Fatalf("the protected handler ran %d times", ran)
	}
	line := "[Touchque] TQ_API_KEY and TQ_API_SECRET are not set: routes guarded by Touchque answer 500 misconfigured."
	if n := strings.Count(buf.String(), line); n != 1 {
		t.Fatalf("logged %d times: %q", n, buf.String())
	}

	shaped := Require(nil, "SEND_MONEY", protected, RequireOptions{
		User:      func(r *http.Request) string { return r.Header.Get("X-User") },
		ErrorBody: func(r GuardRefusal) any { return map[string]any{"error": r.Message, "status": r.Status} },
	})
	want := `{"error":"Two-factor approval is not configured correctly.","status":500,"touchque":{"state":"blocked","reason":"misconfigured"}}`
	if rec := serve(shaped, "jane@acme.com", ""); rec.Code != 500 || strings.TrimSpace(rec.Body.String()) != want {
		t.Fatalf("ErrorBody: status=%d body=%s", rec.Code, rec.Body.String())
	}
	if ran != 0 {
		t.Fatalf("the protected handler ran %d times", ran)
	}

	defer func() {
		if recover() == nil {
			t.Fatal("Require(nil, …) without RequireOptions.User must still panic")
		}
	}()
	Require(nil, "SEND_MONEY", protected, RequireOptions{})
}

func TestRequire_NilClientIsBuiltFromTheEnvironmentOnFirstUse(t *testing.T) {
	noKeys(t)
	api := startFakeAPI(t)
	api.link("jane@acme.com")
	handler := requireHandler(nil, "SEND_MONEY")
	if rec := serve(handler, "jane@acme.com", ""); rec.Code != 500 {
		t.Fatalf("without keys: status=%d body=%s", rec.Code, rec.Body.String())
	}

	t.Setenv("TQ_API_KEY", "tq_test_key")
	t.Setenv("TQ_API_SECRET", "test_secret")
	t.Setenv("TQ_API_URL", api.baseURL)
	first := serve(handler, "jane@acme.com", "")
	var body struct {
		Token string `json:"token"`
	}
	if first.Code != 202 || json.Unmarshal(first.Body.Bytes(), &body) != nil || body.Token == "" {
		t.Fatalf("with keys: status=%d body=%s", first.Code, first.Body.String())
	}
	api.approve("")
	if done := serve(handler, "jane@acme.com", body.Token); done.Code != 200 || !strings.Contains(done.Body.String(), `"done":true`) {
		t.Fatalf("approved: status=%d body=%s", done.Code, done.Body.String())
	}
}

// ── ErrorBody: the app's own error shape ─────────────────────────────────

func errorBodyHandler(c *Client, errorBody func(GuardRefusal) any, logger *slog.Logger) http.Handler {
	return Require(c, "SEND_MONEY", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"done":true}`))
	}), RequireOptions{
		User:      func(r *http.Request) string { return r.Header.Get("X-User") },
		ErrorBody: errorBody,
		Logger:    logger,
	})
}

func TestRequire_ErrorBodyObjectIsMergedWithTheStep(t *testing.T) {
	api := startFakeAPI(t)
	api.link("jane@acme.com")
	var seen []GuardRefusal
	handler := errorBodyHandler(api.client(t), func(r GuardRefusal) any {
		seen = append(seen, r)
		return map[string]any{"message": r.Message, "code": r.Code, "touchque": "mine"}
	}, nil)

	first := serve(handler, "jane@acme.com", "")
	var step struct {
		Touchque Step   `json:"touchque"`
		Token    string `json:"token"`
	}
	if first.Code != 202 || json.Unmarshal(first.Body.Bytes(), &step) != nil || step.Token == "" || len(seen) != 0 {
		t.Fatalf("a 202 step is sent as it is: status=%d body=%s calls=%d", first.Code, first.Body.String(), len(seen))
	}

	api.reject("")
	res := serve(handler, "jane@acme.com", step.Token)
	want := `{"code":"rejected","message":"The approval was rejected.","touchque":{"state":"rejected","requestId":"` +
		step.Touchque.RequestID + `"}}`
	if res.Code != 403 || strings.TrimSpace(res.Body.String()) != want || res.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("status=%d headers=%v body=%s", res.Code, res.Header(), res.Body.String())
	}
	if len(seen) != 1 || seen[0].Status != 403 || seen[0].Code != "rejected" || seen[0].Message != "The approval was rejected." ||
		seen[0].Touchque.State != StepRejected || seen[0].Touchque.RequestID != step.Touchque.RequestID {
		t.Fatalf("refusal = %+v", seen)
	}

	// A struct that encodes to an object is merged as well.
	anon := serve(errorBodyHandler(api.client(t), func(r GuardRefusal) any {
		return struct {
			Error string `json:"error"`
		}{r.Message}
	}, nil), "", "")
	if want := `{"error":"Sign in first.","touchque":{"state":"blocked","reason":"unauthenticated"}}`; anon.Code != 401 ||
		strings.TrimSpace(anon.Body.String()) != want {
		t.Fatalf("struct: status=%d body=%s", anon.Code, anon.Body.String())
	}
}

func TestRequire_ErrorBodyAnythingButAnObjectIsSentAsItIs(t *testing.T) {
	for want, value := range map[string]any{`"Sign in first"`: "Sign in first", `["refused"]`: []string{"refused"}, `null`: nil, `7`: 7} {
		rec := serve(errorBodyHandler(&Client{apiSecret: "shh"}, func(GuardRefusal) any { return value }, nil), "", "")
		if rec.Code != 401 || strings.TrimSpace(rec.Body.String()) != want || rec.Header().Get("Content-Type") != "application/json" {
			t.Errorf("%v: status=%d body=%s", value, rec.Code, rec.Body.String())
		}
	}
}

func TestRequire_ErrorBodyThatFailsSendsTheDefaultBody(t *testing.T) {
	const defaultBody = `{"touchque":{"state":"blocked","reason":"unauthenticated"},"error":{"code":"unauthenticated","message":"Sign in first."}}`
	for name, errorBody := range map[string]func(GuardRefusal) any{
		"a panic":       func(GuardRefusal) any { panic("boom") },
		"not encodable": func(GuardRefusal) any { return func() {} },
	} {
		var buf bytes.Buffer
		rec := serve(errorBodyHandler(&Client{apiSecret: "shh"}, errorBody, slog.New(slog.NewTextHandler(&buf, nil))), "", "")
		if rec.Code != 401 || strings.TrimSpace(rec.Body.String()) != defaultBody {
			t.Errorf("%s: status=%d body=%s", name, rec.Code, rec.Body.String())
		}
		if !strings.Contains(buf.String(), "[Touchque] ErrorBody failed") {
			t.Errorf("%s: logged %q", name, buf.String())
		}
	}
}

func TestRequire_ErrorBodyKeepsStatusAndRetryAfter(t *testing.T) {
	api := startFakeAPI(t)
	api.link("jane@acme.com")
	api.opts(map[string]interface{}{"frozen": true})
	rec := serve(errorBodyHandler(api.client(t), func(r GuardRefusal) any {
		return map[string]string{"code": r.Code, "message": r.Message}
	}, nil), "jane@acme.com", "")
	want := `{"code":"frozen","message":"Too many rejected approvals. Try again later.","touchque":{"state":"frozen","caseCode":"REF-USE","retryAfter":900}}`
	if rec.Code != 423 || strings.TrimSpace(rec.Body.String()) != want ||
		rec.Header().Get("Retry-After") != "900" || rec.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("status=%d headers=%v body=%s", rec.Code, rec.Header(), rec.Body.String())
	}
}

func TestRequire_RefusalsCarryTheTouchqueStateHeaders(t *testing.T) {
	api := startFakeAPI(t)
	api.link("jane@acme.com")
	handler := errorBodyHandler(api.client(t), func(GuardRefusal) any { return "refused" }, nil)
	anon := serve(handler, "", "")
	if anon.Code != 401 || strings.TrimSpace(anon.Body.String()) != `"refused"` ||
		anon.Header().Get("X-Touchque-State") != "blocked" || anon.Header().Get("X-Touchque-Reason") != "unauthenticated" {
		t.Fatalf("401: %d %v %s", anon.Code, anon.Header(), anon.Body.String())
	}
	first := serve(handler, "jane@acme.com", "")
	var step struct {
		Token string `json:"token"`
	}
	if first.Code != 202 || json.Unmarshal(first.Body.Bytes(), &step) != nil || first.Header().Get("X-Touchque-State") != "" {
		t.Fatalf("202: %d %v", first.Code, first.Header())
	}
	api.reject("")
	res := serve(handler, "jane@acme.com", step.Token)
	if res.Code != 403 || res.Header().Get("X-Touchque-State") != "rejected" || res.Header().Get("X-Touchque-Reason") != "" {
		t.Fatalf("403: %d %v", res.Code, res.Header())
	}
}

func TestRequire_ErrorBodyGetsACopyOfTheStep(t *testing.T) {
	api := startFakeAPI(t)
	api.link("jane@acme.com")
	handler := Require(api.client(t), "SEND_MONEY", http.NotFoundHandler(), RequireOptions{
		User:    func(r *http.Request) string { return r.Header.Get("X-User") },
		Details: func(*http.Request) []LoginDetail { return []LoginDetail{{Label: "Amount", Value: "5 EUR"}} },
		ErrorBody: func(r GuardRefusal) any {
			r.Touchque.State = StepApproved
			r.Touchque.Details[0].Value = "1 EUR" // the copy, never the step that is sent
			return map[string]string{"code": r.Code}
		},
	})
	var first struct {
		Touchque Step   `json:"touchque"`
		Token    string `json:"token"`
	}
	_ = json.Unmarshal(serve(handler, "jane@acme.com", "").Body.Bytes(), &first)
	api.reject("")
	res := serve(handler, "jane@acme.com", first.Token)
	want := `{"code":"rejected","touchque":{"state":"rejected","requestId":"` + first.Touchque.RequestID +
		`","details":[{"label":"Amount","value":"5 EUR"}]}}`
	if res.Code != 403 || strings.TrimSpace(res.Body.String()) != want || res.Header().Get("X-Touchque-State") != "rejected" {
		t.Fatalf("status=%d body=%s", res.Code, res.Body.String())
	}
}
