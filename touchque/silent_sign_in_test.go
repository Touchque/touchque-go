package touchque

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
)

// Silent sign-ins, against the shared fake API (and a few hand-made servers
// for the failure paths).

var silentCodes = []string{"known_browser", "recent_approval", "same_phone", "familiar_network", "no_risk_signal"}

// silentVectors returns the proof as the browser sends it in X-TouchQue-Browser
// (base64url JSON) and its key's RFC 7638 thumbprint, from the shared vectors.
func silentVectors(t *testing.T) (proof, thumbprint string) {
	t.Helper()
	var fx struct {
		BrowserProof struct {
			Thumbprint struct {
				Expected string `json:"expected"`
			} `json:"thumbprint"`
			Cases []struct {
				Name  string      `json:"name"`
				Proof interface{} `json:"proof"`
			} `json:"cases"`
		} `json:"browserProof"`
	}
	readFixture(t, "silent-sign-in-vectors.json", &fx)
	for _, c := range fx.BrowserProof.Cases {
		if s, ok := c.Proof.(string); ok && c.Name == "validHeaderEncoding" {
			proof = s
		}
	}
	if proof == "" || fx.BrowserProof.Thumbprint.Expected == "" {
		t.Fatal("silent-sign-in-vectors.json has no validHeaderEncoding proof or thumbprint")
	}
	return proof, fx.BrowserProof.Thumbprint.Expected
}

func reasonCodes(rs []RiskReason) []string {
	out := []string{}
	for _, r := range rs {
		out = append(out, r.Code)
	}
	return out
}

func paths(api *fakeAPI) []string {
	out := []string{}
	for _, c := range api.calls() {
		out = append(out, c["path"].(string))
	}
	return out
}

func intPtr(n int) *int { return &n }

// ── Risk resource ─────────────────────────────────────────────────────

func TestRisk_CheckAsksForNoKeyThenANewBrowserAndSendsNothingToThePhone(t *testing.T) {
	proof, _ := silentVectors(t)
	api := startFakeAPI(t)
	api.link("jane@acme.com")
	c := api.client(t)
	ctx := context.Background()

	res, err := c.Risk.Check(ctx, RiskCheckOptions{ExternalUsername: "jane@acme.com"})
	if err != nil || !res.Prompt || res.Assurance != "normal" || res.SilentMode != "enforce" || !reflect.DeepEqual(reasonCodes(res.Reasons), []string{"no_browser_key"}) {
		t.Fatalf("expected a prompt with no_browser_key: %+v %v", res, err)
	}
	if api.lastCheck()["browserProof"] != nil {
		t.Fatal("no proof was given, none may be sent")
	}

	res, err = c.Risk.Check(ctx, RiskCheckOptions{
		ExternalUsername: "jane@acme.com", Type: "LOGIN", ClientIP: "203.0.113.7", UserAgent: "UA", BrowserProof: proof, MaxAgeSeconds: intPtr(3600),
	})
	if err != nil || !res.Prompt || len(res.Reasons) != 1 || res.Reasons[0].Code != "new_browser" ||
		res.Reasons[0].Text != "This browser has not been approved on the phone for this account" {
		t.Fatalf("expected a prompt with new_browser: %+v %v", res, err)
	}
	want := map[string]interface{}{
		"externalUsername": "jane@acme.com", "type": "LOGIN", "clientIp": "203.0.113.7", "userAgent": "UA",
		"browserProof": proof, "maxAgeSeconds": float64(3600),
	}
	if got := api.lastCheck(); !reflect.DeepEqual(got, want) {
		t.Fatalf("unexpected check body:\n got: %v\nwant: %v", got, want)
	}
	if n := len(callsTo(api, "/login/request")); n != 0 {
		t.Fatalf("a check never pushes, got %d pushes", n)
	}
}

func TestRisk_SilentAnswerAndWhatStillAsks(t *testing.T) {
	proof, _ := silentVectors(t)
	api := startFakeAPI(t)
	api.link("jane@acme.com")
	api.opts(map[string]interface{}{"silent": true})
	c := api.client(t)
	ctx := context.Background()

	res, err := c.Risk.Check(ctx, RiskCheckOptions{ExternalUsername: "jane@acme.com", BrowserProof: proof})
	if err != nil || res.Prompt || res.Assurance != "high" || !reflect.DeepEqual(reasonCodes(res.Reasons), silentCodes) {
		t.Fatalf("expected a silent answer: %+v %v", res, err)
	}
	critical, err := c.Risk.Check(ctx, RiskCheckOptions{ExternalUsername: "jane@acme.com", Type: "SEND_MONEY", BrowserProof: proof})
	if err != nil || !critical.Prompt || !reflect.DeepEqual(critical.Reasons, []RiskReason{{Code: "critical_action", Text: "The action is critical"}}) {
		t.Fatalf("a critical action always asks: %+v %v", critical, err)
	}
	unlinked, err := c.Risk.Check(ctx, RiskCheckOptions{ExternalUsername: "nobody@acme.com", BrowserProof: proof})
	if err != nil || !unlinked.Prompt || !reflect.DeepEqual(reasonCodes(unlinked.Reasons), []string{"phone_not_linked"}) {
		t.Fatalf("an unlinked user is asked: %+v %v", unlinked, err)
	}
}

func TestRisk_MaxAgeSecondsZeroIsSent(t *testing.T) {
	api := startFakeAPI(t)
	api.link("jane@acme.com")
	c := api.client(t)
	if _, err := c.Risk.Check(context.Background(), RiskCheckOptions{ExternalUsername: "jane@acme.com", MaxAgeSeconds: intPtr(0)}); err != nil {
		t.Fatal(err)
	}
	if v, ok := api.lastCheck()["maxAgeSeconds"]; !ok || v != float64(0) {
		t.Fatalf("maxAgeSeconds 0 (always ask) must be sent, got %v", api.lastCheck())
	}
}

func TestRisk_LoginRequestCarriesTheProofAndTheApprovalMakesTheBrowserKnownUntilForgotten(t *testing.T) {
	proof, thumbprint := silentVectors(t)
	api := startFakeAPI(t)
	api.link("jane@acme.com")
	c := api.client(t)
	ctx := context.Background()

	req, err := c.Login.RequestWithOptions(LoginRequestOptions{ExternalUsername: "jane@acme.com", Type: "LOGIN", BrowserProof: proof})
	if err != nil {
		t.Fatal(err)
	}
	if body := callsTo(api, "/login/request")[0]["body"].(map[string]interface{}); body["browserProof"] != proof {
		t.Fatalf("the proof must go with the push, got %v", body)
	}
	if list, err := c.Risk.Browsers(ctx, RiskBrowsersOptions{ExternalUsername: "jane@acme.com"}); err != nil || list.Browsers == nil || len(list.Browsers) != 0 {
		t.Fatalf("no browser is known before the approval: %+v %v", list, err)
	}
	if got := callsTo(api, "/risk/browsers"); len(got) != 1 || got[0]["url"] != "/risk/browsers?externalUsername=jane%40acme.com" {
		t.Fatalf("expected the user as a query parameter, got %v", got)
	}

	api.approve(req.RequestID)
	list, err := c.Risk.Browsers(ctx, RiskBrowsersOptions{ExternalUsername: "jane@acme.com"})
	if err != nil || len(list.Browsers) != 1 {
		t.Fatalf("expected one known browser: %+v %v", list, err)
	}
	b := list.Browsers[0]
	if b.Thumbprint != thumbprint || b.LastMfaMethod != "push" || b.LastSilentAt != "" || b.LastMfaAt == "" || b.CreatedAt == "" {
		t.Fatalf("unexpected browser: %+v", b)
	}

	if res, err := c.Risk.ForgetBrowsers(ctx, ForgetBrowsersOptions{ExternalUsername: "jane@acme.com", Thumbprint: "other"}); err != nil || res.Forgotten != 0 {
		t.Fatalf("another thumbprint forgets nothing: %+v %v", res, err)
	}
	if res, err := c.Risk.ForgetBrowsers(ctx, ForgetBrowsersOptions{ExternalUsername: "jane@acme.com", Thumbprint: thumbprint}); err != nil || res.Forgotten != 1 {
		t.Fatalf("expected one forgotten: %+v %v", res, err)
	}
	if list, _ := c.Risk.Browsers(ctx, RiskBrowsersOptions{ExternalUsername: "jane@acme.com"}); len(list.Browsers) != 0 {
		t.Fatalf("expected no browser left: %+v", list)
	}
	forget := callsTo(api, "/risk/browsers/forget")
	if body := forget[len(forget)-1]["body"].(map[string]interface{}); !reflect.DeepEqual(body, map[string]interface{}{"externalUsername": "jane@acme.com", "thumbprint": thumbprint}) {
		t.Fatalf("unexpected forget body: %v", body)
	}

	// Without a thumbprint every browser of the user is forgotten.
	if _, err := c.Login.RequestWithOptions(LoginRequestOptions{ExternalUsername: "jane@acme.com", Type: "LOGIN", BrowserProof: proof}); err != nil {
		t.Fatal(err)
	}
	api.approve("")
	if res, err := c.Risk.ForgetBrowsers(ctx, ForgetBrowsersOptions{ExternalUsername: "jane@acme.com"}); err != nil || res.Forgotten != 1 {
		t.Fatalf("expected every browser forgotten: %+v %v", res, err)
	}
	forget = callsTo(api, "/risk/browsers/forget")
	if body := forget[len(forget)-1]["body"].(map[string]interface{}); !reflect.DeepEqual(body, map[string]interface{}{"externalUsername": "jane@acme.com"}) {
		t.Fatalf("no thumbprint may be sent to forget all, got %v", body)
	}
}

func TestRisk_AProvisionalApprovalDoesNotMakeTheBrowserKnown(t *testing.T) {
	proof, _ := silentVectors(t)
	api := startFakeAPI(t)
	api.link("jane@acme.com")
	c := api.client(t)
	req, err := c.Login.RequestWithOptions(LoginRequestOptions{ExternalUsername: "jane@acme.com", Type: "LOGIN", BrowserProof: proof})
	if err != nil {
		t.Fatal(err)
	}
	api.approveProvisional(req.RequestID)
	if list, _ := c.Risk.Browsers(context.Background(), RiskBrowsersOptions{ExternalUsername: "jane@acme.com"}); len(list.Browsers) != 0 {
		t.Fatalf("an approval during a call must not make the browser known: %+v", list)
	}
}

func TestRisk_AMissingUserIsAClearErrorBeforeAnyRequest(t *testing.T) {
	c := silentClient(t)
	ctx := context.Background()
	var cfg *ConfigError
	if _, err := c.Risk.Check(ctx, RiskCheckOptions{}); !errors.As(err, &cfg) {
		t.Fatalf("expected *ConfigError, got %T %v", err, err)
	}
	if _, err := c.Risk.Browsers(ctx, RiskBrowsersOptions{}); !errors.As(err, &cfg) {
		t.Fatalf("expected *ConfigError, got %T %v", err, err)
	}
	if _, err := c.Risk.ForgetBrowsers(ctx, ForgetBrowsersOptions{}); !errors.As(err, &cfg) {
		t.Fatalf("expected *ConfigError, got %T %v", err, err)
	}
}

func TestRisk_CheckHonoursTheContext(t *testing.T) {
	// The server would answer silent: only the cancelled context can fail it.
	c, closeFn := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"prompt":false,"assurance":"high","reasons":[]}`))
	})
	defer closeFn()
	if res, err := c.Risk.Check(context.Background(), RiskCheckOptions{ExternalUsername: "jane@acme.com"}); err != nil || res.Prompt {
		t.Fatalf("expected a silent answer: %+v %v", res, err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := c.Risk.Check(ctx, RiskCheckOptions{ExternalUsername: "jane@acme.com"}); err == nil {
		t.Fatal("a cancelled context must fail the check")
	}
}

// ── Guard ─────────────────────────────────────────────────────────────

func silentInput(proof string) GuardInput {
	return GuardInput{User: "jane@acme.com", Action: "LOGIN", IP: "203.0.113.7", UserAgent: "UA", BrowserProof: proof, SilentSignIn: true}
}

func TestSilentGuard_AKnownBrowserWithNothingNewIsApprovedAtOnceWithNoPush(t *testing.T) {
	proof, _ := silentVectors(t)
	api := startFakeAPI(t)
	api.link("jane@acme.com")
	api.opts(map[string]interface{}{"silent": true})
	c := api.client(t)

	res := runGuard(c, silentInput(proof))
	a := res.Approved
	if res.Status != 200 || a == nil {
		t.Fatalf("expected an approval: %d %+v", res.Status, res.Body)
	}
	if a.RequestID != "silent" || a.User != "jane@acme.com" || a.Action != "LOGIN" || a.ConfirmedVia != "SILENT" ||
		a.Assurance == nil || a.Assurance.Method != "silent" || a.Assurance.PhishingResistant || a.ApprovalProof != nil {
		t.Fatalf("unexpected silent approval: %+v", a)
	}
	if !reflect.DeepEqual(reasonCodes(a.Reasons), silentCodes) {
		t.Fatalf("unexpected reasons: %+v", a.Reasons)
	}
	want := map[string]interface{}{"externalUsername": "jane@acme.com", "type": "LOGIN", "clientIp": "203.0.113.7", "userAgent": "UA", "browserProof": proof}
	if got := api.lastCheck(); !reflect.DeepEqual(got, want) {
		t.Fatalf("unexpected check body:\n got: %v\nwant: %v", got, want)
	}
	if got := paths(api); !reflect.DeepEqual(got, []string{"/risk/check"}) {
		t.Fatalf("expected only the check, got %v", got)
	}
}

func TestSilentGuard_OtherwiseTheUsualPushStartsCarryingTheProof(t *testing.T) {
	proof, thumbprint := silentVectors(t)
	api := startFakeAPI(t)
	api.link("jane@acme.com")
	c := api.client(t)
	in := silentInput(proof)

	first := runGuard(c, in)
	if first.Status != 202 || first.Body.Touchque.State != StepWaiting {
		t.Fatalf("expected the usual push: %d %+v", first.Status, first.Body)
	}
	if got := paths(api); !reflect.DeepEqual(got, []string{"/risk/check", "/login/request"}) {
		t.Fatalf("expected the check then the push, got %v", got)
	}
	if body := callsTo(api, "/login/request")[0]["body"].(map[string]interface{}); body["browserProof"] != proof {
		t.Fatalf("the push must carry the proof, got %v", body)
	}

	// Polling with the token never asks again, even if the answer would now be silent.
	api.opts(map[string]interface{}{"silent": true})
	poll := in
	poll.Token = first.Body.Token
	if res := runGuard(c, poll); res.Body == nil || res.Body.Touchque.State != StepWaiting {
		t.Fatalf("expected still waiting: %+v", res)
	}
	if n := len(callsTo(api, "/risk/check")); n != 1 {
		t.Fatalf("a poll must not check again, got %d checks", n)
	}

	api.approve(first.Body.Touchque.RequestID)
	done := runGuard(c, poll)
	if done.Approved == nil || done.Approved.ConfirmedVia != "DEVICE" || done.Approved.Assurance == nil || done.Approved.Assurance.Method != "push" || done.Approved.Reasons != nil {
		t.Fatalf("expected the push approval: %+v", done)
	}
	list, err := c.Risk.Browsers(context.Background(), RiskBrowsersOptions{ExternalUsername: "jane@acme.com"})
	if err != nil || len(list.Browsers) != 1 || list.Browsers[0].Thumbprint != thumbprint {
		t.Fatalf("the approval must make the browser known: %+v %v", list, err)
	}
}

func TestSilentGuard_ACriticalActionAlwaysAsksWithNumberMatching(t *testing.T) {
	proof, _ := silentVectors(t)
	api := startFakeAPI(t)
	api.link("jane@acme.com")
	api.opts(map[string]interface{}{"silent": true})
	c := api.client(t)
	in := silentInput(proof)
	in.Action = "SEND_MONEY"
	res := runGuard(c, in)
	if res.Approved != nil || res.Body.Touchque.State != StepWaiting || res.Body.Touchque.Number != "47" {
		t.Fatalf("expected a push with number matching: %+v", res.Body)
	}
	if api.lastCheck()["type"] != "SEND_MONEY" {
		t.Fatalf("the check must name the action, got %v", api.lastCheck())
	}
}

func TestSilentGuard_FailsClosedAnyErrorOrAnythingButPromptFalseStartsThePush(t *testing.T) {
	proof, _ := silentVectors(t)
	cases := []struct {
		name  string
		check func(w http.ResponseWriter)
	}{
		{"server error", func(w http.ResponseWriter) { w.WriteHeader(500); _, _ = w.Write([]byte(`{"error":"boom"}`)) }},
		{"server without silent sign-ins", func(w http.ResponseWriter) { w.WriteHeader(404); _, _ = w.Write([]byte(`{"error":"no route"}`)) }},
		{"rate limited", func(w http.ResponseWriter) { w.WriteHeader(429); _, _ = w.Write([]byte(`{"code":"rate_limited"}`)) }},
		{"prompt as a string", func(w http.ResponseWriter) {
			_, _ = w.Write([]byte(`{"prompt":"false","assurance":"high","reasons":[]}`))
		}},
		{"prompt missing", func(w http.ResponseWriter) { _, _ = w.Write([]byte(`{"assurance":"high","reasons":[]}`)) }},
		{"prompt null", func(w http.ResponseWriter) { _, _ = w.Write([]byte(`{"prompt":null}`)) }},
		{"not JSON", func(w http.ResponseWriter) { _, _ = w.Write([]byte(`prompt=false`)) }},
		{"a JSON array", func(w http.ResponseWriter) { _, _ = w.Write([]byte(`[{"prompt":false}]`)) }},
		{"network failure", func(w http.ResponseWriter) {
			conn, _, err := w.(http.Hijacker).Hijack()
			if err == nil {
				_ = conn.Close()
			}
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var pushes []map[string]interface{}
			c, closeFn := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/risk/check":
					tc.check(w)
				case "/login/request":
					var body map[string]interface{}
					_ = json.NewDecoder(r.Body).Decode(&body)
					pushes = append(pushes, body)
					_ = json.NewEncoder(w).Encode(map[string]interface{}{"requestId": "req_1"})
				default:
					t.Errorf("unexpected call %s %s", r.Method, r.URL.Path)
					w.WriteHeader(500)
				}
			})
			defer closeFn()
			res := runGuard(c, silentInput(proof))
			if res.Approved != nil || res.Status != 202 || res.Body.Touchque.State != StepWaiting || res.Body.Touchque.RequestID != "req_1" {
				t.Fatalf("expected the usual push: %d %+v %+v", res.Status, res.Approved, res.Body)
			}
			if len(pushes) != 1 || pushes[0]["browserProof"] != proof {
				t.Fatalf("expected one push carrying the proof, got %v", pushes)
			}
		})
	}
}

func TestSilentGuard_OffByDefaultWithoutAProofOrWithAProofTooLargeToBeOne(t *testing.T) {
	proof, _ := silentVectors(t)
	api := startFakeAPI(t)
	api.link("jane@acme.com")
	api.opts(map[string]interface{}{"silent": true})
	c := api.client(t)

	off := silentInput(proof)
	off.SilentSignIn = false
	if res := runGuard(c, off); res.Status != 202 {
		t.Fatalf("off by default: %d %+v", res.Status, res.Approved)
	}
	noProof := silentInput("")
	if res := runGuard(c, noProof); res.Status != 202 {
		t.Fatalf("no proof: %d %+v", res.Status, res.Approved)
	}
	tooLarge := silentInput(strings.Repeat("x", 5000))
	if res := runGuard(c, tooLarge); res.Status != 202 {
		t.Fatalf("too large: %d %+v", res.Status, res.Approved)
	}
	pushes := callsTo(api, "/login/request")
	if len(pushes) != 3 {
		t.Fatalf("expected three pushes, got %d", len(pushes))
	}
	// Off, the proof still goes with the push: its approval makes the browser known.
	if pushes[0]["body"].(map[string]interface{})["browserProof"] != proof {
		t.Fatalf("expected the proof on the push, got %v", pushes[0]["body"])
	}
	for _, p := range pushes[1:] {
		if _, ok := p["body"].(map[string]interface{})["browserProof"]; ok {
			t.Fatalf("no proof (or one too large) may be sent, got %v", p["body"])
		}
	}
	if n := len(callsTo(api, "/risk/check")); n != 0 {
		t.Fatalf("expected no check, got %d", n)
	}
}

func TestSilentGuard_MaxAgeSecondsIsSentWithTheCheck(t *testing.T) {
	proof, _ := silentVectors(t)
	api := startFakeAPI(t)
	api.link("jane@acme.com")
	c := api.client(t)
	in := silentInput(proof)
	in.SilentSignInMaxAgeSeconds = intPtr(0)
	runGuard(c, in)
	if v, ok := api.lastCheck()["maxAgeSeconds"]; !ok || v != float64(0) {
		t.Fatalf("expected maxAgeSeconds 0, got %v", api.lastCheck())
	}
}

// ── Adapters read X-TouchQue-Browser only when SilentSignIn is on ─────

func silentRequireHandler(c *Client, silent bool, ran *int) http.Handler {
	protected := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		*ran++
		approval, _ := ApprovalFromContext(r.Context())
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"done": true, "touchque": approval})
	})
	return Require(c, "LOGIN", protected, RequireOptions{
		User:         func(*http.Request) string { return "jane@acme.com" },
		SilentSignIn: silent,
	})
}

func TestSilentRequire_TheHandlerRunsAtOnceForAKnownBrowser(t *testing.T) {
	proof, _ := silentVectors(t)
	api := startFakeAPI(t)
	api.link("jane@acme.com")
	api.opts(map[string]interface{}{"silent": true})
	ran := 0
	h := silentRequireHandler(api.client(t), true, &ran)

	req := httptest.NewRequest(http.MethodPost, "/account", nil)
	req.Header.Set(GuardBrowserHeader, proof)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != 200 || ran != 1 {
		t.Fatalf("expected the handler to run: %d %s", rec.Code, rec.Body.String())
	}
	var out struct {
		Touchque Approval `json:"touchque"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	if out.Touchque.ConfirmedVia != "SILENT" || out.Touchque.Assurance == nil || out.Touchque.Assurance.Method != "silent" || len(out.Touchque.Reasons) != 5 {
		t.Fatalf("unexpected approval: %+v", out.Touchque)
	}
	if api.lastCheck()["browserProof"] != proof {
		t.Fatalf("the header must reach the check, got %v", api.lastCheck())
	}
}

func TestSilentRequire_WithoutSilentSignInTheHeaderIsIgnored(t *testing.T) {
	proof, _ := silentVectors(t)
	api := startFakeAPI(t)
	api.link("jane@acme.com")
	api.opts(map[string]interface{}{"silent": true})
	ran := 0
	h := silentRequireHandler(api.client(t), false, &ran)

	req := httptest.NewRequest(http.MethodPost, "/account", nil)
	req.Header.Set(GuardBrowserHeader, proof)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != 202 || ran != 0 {
		t.Fatalf("expected the usual push: %d %s", rec.Code, rec.Body.String())
	}
	if n := len(callsTo(api, "/risk/check")); n != 0 {
		t.Fatalf("expected no check, got %d", n)
	}
	if _, ok := callsTo(api, "/login/request")[0]["body"].(map[string]interface{})["browserProof"]; ok {
		t.Fatal("the header must not be read when SilentSignIn is off")
	}
}

func TestSilentRelay_LoginSucceedsWithViaSilentANewBrowserGetsThePushWithTheProof(t *testing.T) {
	proof, _ := silentVectors(t)
	api := startFakeAPI(t)
	api.link("jane@acme.com")
	auth := &authRecorder{}
	h := mountRelay(api.client(t), RelayOptions{
		LoginUser:       func(*http.Request) string { return "jane@acme.com" },
		OnAuthenticated: auth.fn,
		SilentSignIn:    true,
	})

	rec, _ := relayCall(t, h, "POST", "/login", map[string]interface{}{}, withHeader(GuardBrowserHeader, proof))
	if rec.Code != 202 {
		t.Fatalf("expected the push: %d %s", rec.Code, rec.Body.String())
	}
	if body := callsTo(api, "/login/request")[0]["body"].(map[string]interface{}); body["browserProof"] != proof {
		t.Fatalf("the push must carry the proof, got %v", body)
	}
	if len(auth.all()) != 0 {
		t.Fatal("OnAuthenticated must not run before approval")
	}

	api.opts(map[string]interface{}{"silent": true})
	rec, out := relayCall(t, h, "POST", "/login", map[string]interface{}{}, withHeader(GuardBrowserHeader, proof))
	if rec.Code != 200 || out["status"] != "success" || out["requestId"] != "silent" {
		t.Fatalf("expected a silent success: %d %v", rec.Code, out)
	}
	if a, _ := out["assurance"].(map[string]interface{}); a == nil || a["method"] != "silent" {
		t.Fatalf("expected silent assurance, got %v", out["assurance"])
	}
	calls := auth.all()
	if len(calls) != 1 || calls[0] != (AuthenticatedInfo{ExternalUsername: "jane@acme.com", RequestID: "silent", Via: ViaSilent}) {
		t.Fatalf("unexpected OnAuthenticated calls: %+v", calls)
	}
	if n := len(callsTo(api, "/login/request")); n != 1 {
		t.Fatalf("the silent sign-in must not push, got %d pushes", n)
	}
}

func TestSilentRelay_OffByDefault(t *testing.T) {
	proof, _ := silentVectors(t)
	api := startFakeAPI(t)
	api.link("jane@acme.com")
	api.opts(map[string]interface{}{"silent": true})
	h := mountRelay(api.client(t), RelayOptions{LoginUser: func(*http.Request) string { return "jane@acme.com" }})
	rec, _ := relayCall(t, h, "POST", "/login", map[string]interface{}{}, withHeader(GuardBrowserHeader, proof))
	if rec.Code != 202 || len(callsTo(api, "/risk/check")) != 0 {
		t.Fatalf("expected the usual push and no check: %d %s", rec.Code, rec.Body.String())
	}
}
