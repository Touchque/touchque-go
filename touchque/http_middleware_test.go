package touchque

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"reflect"
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

// noKeys: TQ_API_KEY / TQ_API_SECRET unset, no default client built yet, and the "not set" line
// not logged yet in this process.
func noKeys(t *testing.T) {
	t.Helper()
	t.Setenv("TQ_API_KEY", "")
	t.Setenv("TQ_API_SECRET", "")
	t.Setenv("TQ_API_URL", "")
	warnedUnconfigured.Store(false)
	defaultClient.client.Store(nil)
	t.Cleanup(func() {
		warnedUnconfigured.Store(false)
		defaultClient.client.Store(nil)
	})
}

// withKeys points TQ_API_KEY / TQ_API_SECRET / TQ_API_URL at the fake API.
func withKeys(t *testing.T, api *fakeAPI) {
	t.Helper()
	t.Setenv("TQ_API_KEY", "tq_test_key")
	t.Setenv("TQ_API_SECRET", "test_secret")
	t.Setenv("TQ_API_URL", api.baseURL)
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

	withKeys(t, api)
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

// ── WriteGuardResult: the answer RunGuard's caller sends, the same as Require's ──

// handlerGuard is the guard inside a handler: RunGuard, then WriteGuardResult.
func handlerGuard(c *Client, action string, errorBody func(GuardRefusal) any) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		res := RunGuard(r.Context(), c, GuardInput{
			User: r.Header.Get("X-User"), Action: action, IP: hostOnly(r.RemoteAddr), UserAgent: r.UserAgent(),
			Token: r.Header.Get(GuardTokenHeader),
		})
		if res.Approved == nil {
			WriteGuardResult(w, res, errorBody)
			return
		}
		_, _ = w.Write([]byte(`{"done":true}`))
	})
}

// sentAnswer is what a guard answer carries, the token aside (each answer signs its own).
func sentAnswer(t *testing.T, rec *httptest.ResponseRecorder) (int, map[string]string, any) {
	t.Helper()
	headers := map[string]string{}
	for _, name := range []string{"Content-Type", "Cache-Control", "Retry-After", "X-Touchque-State", "X-Touchque-Reason"} {
		if v := rec.Header().Get(name); v != "" {
			headers[name] = v
		}
	}
	var body any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("not JSON: %s", rec.Body.String())
	}
	if obj, ok := body.(map[string]any); ok {
		delete(obj, "token")
	}
	return rec.Code, headers, body
}

func TestWriteGuardResult_SendsWhatRequireSends(t *testing.T) {
	api := startFakeAPI(t)
	api.link("jane@acme.com")
	c := api.client(t)
	errorBodies := map[string]func(GuardRefusal) any{
		"the default body": nil,
		"an object":        func(r GuardRefusal) any { return map[string]any{"message": r.Message, "code": r.Code} },
		"a string":         func(r GuardRefusal) any { return r.Message },
	}
	token := RunGuard(context.Background(), c, GuardInput{User: "jane@acme.com", Action: "SEND_MONEY"}).Body.Token
	cases := []struct {
		name, action, user, token string
		before                    func()
		status                    int
	}{
		{name: "202 waiting poll", action: "SEND_MONEY", user: "jane@acme.com", token: token, status: 202},
		{name: "401 nobody signed in", action: "SEND_MONEY", status: 401},
		{name: "403 rejected", action: "SEND_MONEY", user: "jane@acme.com", token: token, before: func() { api.reject("") }, status: 403},
		{name: "429 rate limited", action: "SEND_MONEY", user: "jane@acme.com", status: 429,
			before: func() { api.opts(map[string]interface{}{"rateLimited": true}) }},
		{name: "500 misconfigured", action: "NOT_DEFINED", user: "jane@acme.com", status: 500,
			before: func() { api.opts(map[string]interface{}{"rateLimited": false}) }},
	}
	for _, tc := range cases {
		if tc.before != nil {
			tc.before()
		}
		for name, errorBody := range errorBodies {
			adapter := Require(c, tc.action, http.NotFoundHandler(), RequireOptions{
				User: func(r *http.Request) string { return r.Header.Get("X-User") }, ErrorBody: errorBody,
			})
			wantStatus, wantHeaders, wantBody := sentAnswer(t, serve(adapter, tc.user, tc.token))
			status, headers, body := sentAnswer(t, serve(handlerGuard(c, tc.action, errorBody), tc.user, tc.token))
			if wantStatus != tc.status || status != wantStatus || !reflect.DeepEqual(headers, wantHeaders) ||
				!reflect.DeepEqual(body, wantBody) {
				t.Errorf("%s, %s:\n Require          %d %v %v\n WriteGuardResult %d %v %v",
					tc.name, name, wantStatus, wantHeaders, wantBody, status, headers, body)
			}
		}
	}
}

func TestWriteGuardResult_HeadersStatusAndBody(t *testing.T) {
	limited := GuardResult{Status: 429, Body: &GuardBody{Touchque: Step{State: StepRateLimited, RetryAfter: 60}, Token: "t"}}
	rec := httptest.NewRecorder()
	WriteGuardResult(rec, limited, nil)
	if rec.Code != 429 || strings.TrimSpace(rec.Body.String()) != `{"touchque":{"state":"rate_limited","retryAfter":60},"token":"t"}` ||
		rec.Header().Get("Content-Type") != "application/json" || rec.Header().Get("Cache-Control") != "no-store" ||
		rec.Header().Get("Retry-After") != "60" || rec.Header().Get("X-Touchque-State") != "rate_limited" ||
		rec.Header().Get("X-Touchque-Reason") != "" {
		t.Fatalf("429: %d %v %s", rec.Code, rec.Header(), rec.Body.String())
	}

	rec = httptest.NewRecorder()
	WriteGuardResult(rec, limited, func(r GuardRefusal) any { return map[string]any{"code": r.Code} })
	if want := `{"code":"rate_limited","touchque":{"state":"rate_limited","retryAfter":60}}`; rec.Code != 429 ||
		strings.TrimSpace(rec.Body.String()) != want || rec.Header().Get("Retry-After") != "60" {
		t.Fatalf("429 with ErrorBody: %d %v %s", rec.Code, rec.Header(), rec.Body.String())
	}

	rec = httptest.NewRecorder()
	called := false
	WriteGuardResult(rec, GuardResult{Status: 202, Body: &GuardBody{Touchque: Step{State: StepEnroll, Reason: "enrollment_off"}, Token: "t"}},
		func(GuardRefusal) any { called = true; return nil })
	if rec.Code != 202 || called || rec.Header().Get("X-Touchque-State") != "" ||
		strings.TrimSpace(rec.Body.String()) != `{"touchque":{"state":"enroll","reason":"enrollment_off"},"token":"t"}` {
		t.Fatalf("202: %d %v %s (ErrorBody called: %v)", rec.Code, rec.Header(), rec.Body.String(), called)
	}

	rec = httptest.NewRecorder()
	WriteGuardResult(rec, GuardResult{Status: 200, Approved: &Approval{RequestID: "req_1"}}, nil)
	if rec.Body.Len() != 0 || len(rec.Header()) != 0 {
		t.Fatalf("an approval writes nothing: %v %s", rec.Header(), rec.Body.String())
	}
}

func TestWriteGuardResult_ErrorBodyThatFailsLogsToTheClientsLogger(t *testing.T) {
	var buf bytes.Buffer
	c := NewClient(&Config{APIKey: "tq_test_key", APISecret: "shh", BaseURL: "http://127.0.0.1:1", Logger: slog.New(slog.NewTextHandler(&buf, nil))})
	res := RunGuard(context.Background(), c, GuardInput{Action: "SEND_MONEY"}) // nobody signed in: 401
	rec := httptest.NewRecorder()
	WriteGuardResult(rec, res, func(GuardRefusal) any { panic("boom") })
	const defaultBody = `{"touchque":{"state":"blocked","reason":"unauthenticated"},"error":{"code":"unauthenticated","message":"Sign in first."}}`
	if rec.Code != 401 || strings.TrimSpace(rec.Body.String()) != defaultBody {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(buf.String(), "[Touchque] ErrorBody failed") {
		t.Fatalf("logged %q", buf.String())
	}
}

func TestWriteGuardResult_AnErrorBodyTooDeepToEncodeSendsTheDefaultBody(t *testing.T) {
	var deepList any = "x"
	var deepObject any = "x"
	for i := 0; i < 10001; i++ { // deeper than encoding/json reads back
		deepList = []any{deepList}
		deepObject = map[string]any{"a": deepObject}
	}
	const defaultBody = `{"touchque":{"state":"blocked","reason":"unauthenticated"},"error":{"code":"unauthenticated","message":"Sign in first."}}`
	for name, value := range map[string]any{"a list": deepList, "an object": deepObject} {
		var buf bytes.Buffer
		c := NewClient(&Config{APIKey: "tq_test_key", APISecret: "shh", BaseURL: "http://127.0.0.1:1", Logger: slog.New(slog.NewTextHandler(&buf, nil))})
		rec := httptest.NewRecorder()
		WriteGuardResult(rec, RunGuard(context.Background(), c, GuardInput{Action: "SEND_MONEY"}), func(GuardRefusal) any { return value })
		if rec.Code != 401 || strings.TrimSpace(rec.Body.String()) != defaultBody || rec.Header().Get("X-Touchque-State") != "blocked" {
			t.Errorf("%s: status=%d body=%.120s", name, rec.Code, rec.Body.String())
		}
		if !strings.Contains(buf.String(), "[Touchque] ErrorBody failed") {
			t.Errorf("%s: logged %.200q", name, buf.String())
		}
	}
}

// SetDefaultClient replaces the default client (a logger for the null-client path) or forgets it, so the
// environment is read again.
func TestSetDefaultClientReplacesOrForgetsTheDefaultClient(t *testing.T) {
	noKeys(t)
	first, second := startFakeAPI(t), startFakeAPI(t)
	first.link("jane@acme.com")
	second.link("jane@acme.com")
	ctx := context.Background()
	in := GuardInput{User: "jane@acme.com", Action: "LOGIN"}

	withKeys(t, first)
	if res := RunGuard(ctx, nil, in); res.Status != 202 {
		t.Fatalf("first environment: status=%d", res.Status)
	}
	withKeys(t, second) // read once per process: the default client keeps the first one...
	RunGuard(ctx, nil, in)
	if n := len(callsTo(second, "/login/request")); n != 0 {
		t.Fatalf("the default client was rebuilt without a reset: %d pushes on the second API", n)
	}
	SetDefaultClient(nil) // ...until it is forgotten
	if res := RunGuard(ctx, nil, in); res.Status != 202 || len(callsTo(second, "/login/request")) != 1 {
		t.Fatalf("forgotten: status=%d, pushes on the second API %d", res.Status, len(callsTo(second, "/login/request")))
	}

	var buf bytes.Buffer
	SetDefaultClient(NewClient(&Config{APIKey: "tq_test_key", APISecret: "test_secret", BaseURL: "http://127.0.0.1:1",
		TimeoutMs: 1000, Logger: slog.New(slog.NewTextHandler(&buf, nil))})) // nothing listens there: 503
	if res := RunGuard(ctx, nil, in); res.Status != 503 || !strings.Contains(buf.String(), "[Touchque] approval failed") {
		t.Fatalf("replaced: status=%d logged %q", res.Status, buf.String())
	}
	broken := Require(nil, "LOGIN", http.NotFoundHandler(), RequireOptions{
		User:      func(r *http.Request) string { return r.Header.Get("X-User") },
		ErrorBody: func(GuardRefusal) any { panic("boom") },
	})
	if rec := serve(broken, "jane@acme.com", ""); rec.Code != 503 || !strings.Contains(buf.String(), "[Touchque] ErrorBody failed") {
		t.Fatalf("Require(nil, …) logs to the default client's logger: status=%d logged %q", rec.Code, buf.String())
	}
}
