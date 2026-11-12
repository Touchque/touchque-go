package touchque

// Contract tests against the shared fake Touchque API — a real HTTP round
// trip, so request signing is verified too (not just mocked). Same
// scenarios as the Node/Python/PHP SDKs' step-up tests.

import (
	"bytes"
	"log/slog"
	"reflect"
	"strings"
	"testing"
)

func TestContract_StartCheckCompleteFullFlow(t *testing.T) {
	api := startFakeAPI(t)
	api.link("jane@acme.com")
	c := api.client(t)

	step, err := c.Start("SEND_MONEY", "jane@acme.com", StartOptions{
		Details: []LoginDetail{{Label: "Amount", Value: "250 EUR"}}, ReferenceID: "tx-9",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if step.State != StepWaiting || step.Number != "47" { // SEND_MONEY is critical in the fake API
		t.Fatalf("unexpected step: %+v", step)
	}
	if len(step.Details) != 1 || step.Details[0] != (LoginDetail{Label: "Amount", Value: "250 EUR"}) {
		t.Fatalf("unexpected details: %+v", step.Details)
	}

	check1, err := c.Check(step.RequestID)
	if err != nil || check1.State != StepWaiting {
		t.Fatalf("unexpected check: %+v, err=%v", check1, err)
	}
	api.approve(step.RequestID)
	check2, err := c.Check(step.RequestID)
	if err != nil || check2.State != StepApproved {
		t.Fatalf("unexpected check: %+v, err=%v", check2, err)
	}

	approval, err := c.Complete(step.RequestID, "jane@acme.com", "SEND_MONEY", CompleteExpect{
		Details: []LoginDetail{{Label: "Amount", Value: "250 EUR"}}, ReferenceID: "tx-9",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if approval.Assurance == nil || approval.Assurance.Method != "push" || approval.Assurance.PhishingResistant {
		t.Fatalf("unexpected assurance: %+v", approval.Assurance)
	}

	_, err = c.Complete(step.RequestID, "jane@acme.com", "SEND_MONEY", CompleteExpect{
		Details: []LoginDetail{{Label: "Amount", Value: "250 EUR"}}, ReferenceID: "tx-9",
	})
	if err == nil {
		t.Fatal("expected the second Complete() to fail (already used)")
	}
}

func TestContract_CompleteRefusesADifferentAmount(t *testing.T) {
	api := startFakeAPI(t)
	api.link("jane2@acme.com")
	c := api.client(t)

	step, err := c.Start("SEND_MONEY", "jane2@acme.com", StartOptions{Details: []LoginDetail{{Label: "Amount", Value: "250 EUR"}}})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	api.approve(step.RequestID)

	_, err = c.Complete(step.RequestID, "jane2@acme.com", "SEND_MONEY", CompleteExpect{Details: []LoginDetail{{Label: "Amount", Value: "9999 EUR"}}})
	if err == nil {
		t.Fatal("expected Complete() to refuse a different amount")
	}
}

func TestContract_UnknownActionIsAClearConfigError(t *testing.T) {
	api := startFakeAPI(t)
	api.link("jane3@acme.com")
	c := api.client(t)

	_, err := c.Start("NOT_DEFINED", "jane3@acme.com", StartOptions{})
	if _, ok := err.(*ConfigError); !ok {
		t.Fatalf("expected *ConfigError, got %T (%v)", err, err)
	}
}

func TestContract_ActionsDefineCreatesAndUpdates(t *testing.T) {
	api := startFakeAPI(t)
	c := api.client(t)

	critical := true
	if _, err := c.ActionTypes.Define("EXPORT", DefineOptions{Name: "Export data", Critical: &critical}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	var body map[string]interface{}
	for _, call := range api.calls() {
		if call["path"] == "/action-types" {
			body, _ = call["body"].(map[string]interface{})
		}
	}
	if body["type"] != "EXPORT" || body["name"] != "Export data" || body["critical"] != true {
		t.Fatalf("unexpected body: %+v", body)
	}
}

func TestContract_GuardFullFlowViaRequire(t *testing.T) {
	api := startFakeAPI(t)
	api.link("guard@acme.com")
	api.opts(map[string]interface{}{"numberMatch": true})
	c := api.client(t)

	first := runGuard(c, GuardInput{User: "guard@acme.com", Action: "LOGIN"})
	if first.Status != 202 || first.Body.Touchque.State != StepWaiting || first.Body.Touchque.Number != "47" {
		t.Fatalf("unexpected first result: status=%d body=%+v", first.Status, first.Body)
	}
	token := first.Body.Token

	still := runGuard(c, GuardInput{User: "guard@acme.com", Action: "LOGIN", Token: token})
	if still.Status != 202 {
		t.Fatalf("expected 202 while waiting, got %d", still.Status)
	}

	api.approve("")
	done := runGuard(c, GuardInput{User: "guard@acme.com", Action: "LOGIN", Token: token})
	if done.Status != 200 || done.Approved == nil || done.Approved.Assurance.Method != "push" {
		t.Fatalf("unexpected done result: status=%d approved=%+v", done.Status, done.Approved)
	}

	replay := runGuard(c, GuardInput{User: "guard@acme.com", Action: "LOGIN", Token: token})
	if replay.Approved != nil {
		t.Fatal("expected the replayed token to be refused")
	}
}

func TestContract_GuardEnrollThenOfflineCode(t *testing.T) {
	api := startFakeAPI(t)
	c := api.client(t)

	first := runGuard(c, GuardInput{User: "new-offline@acme.com", Action: "LOGIN"})
	if first.Status != 202 || first.Body.Touchque.State != StepEnroll || first.Body.Touchque.Enroll == nil {
		t.Fatalf("unexpected first result: %+v", first.Body)
	}

	api.link("new-offline@acme.com")
	waiting := runGuard(c, GuardInput{User: "new-offline@acme.com", Action: "LOGIN", Token: first.Body.Token})
	if waiting.Body.Touchque.State != StepWaiting {
		t.Fatalf("unexpected waiting result: %+v", waiting.Body)
	}

	off := runGuard(c, GuardInput{User: "new-offline@acme.com", Action: "LOGIN", Token: waiting.Body.Token, Offline: true})
	if off.Body.Touchque.State != StepOffline || off.Body.Touchque.Offline.QRDataURL != "data:image/png;base64,OFFLINE" {
		t.Fatalf("unexpected offline result: %+v", off.Body)
	}

	wrong := runGuard(c, GuardInput{User: "new-offline@acme.com", Action: "LOGIN", Token: off.Body.Token, Code: "ZZZZ999"})
	if wrong.Body.Touchque.Offline == nil || wrong.Body.Touchque.Offline.AttemptsLeft != 4 {
		t.Fatalf("unexpected wrong-code result: %+v", wrong.Body)
	}

	ok := runGuard(c, GuardInput{User: "new-offline@acme.com", Action: "LOGIN", Token: wrong.Body.Token, Code: "ABCD123"})
	if ok.Status != 200 || ok.Approved.Assurance.Method != "offline_code" {
		t.Fatalf("unexpected ok result: status=%d approved=%+v", ok.Status, ok.Approved)
	}
}

func TestContract_GuardPhoneRejectKillsTheOfflineQR(t *testing.T) {
	api := startFakeAPI(t)
	c := api.client(t)
	const user = "reject-offline@acme.com"
	api.link(user)

	start := runGuard(c, GuardInput{User: user, Action: "LOGIN"})
	off := runGuard(c, GuardInput{User: user, Action: "LOGIN", Token: start.Body.Token, Offline: true})
	if off.Body.Touchque.State != StepOffline {
		t.Fatalf("unexpected offline result: %+v", off.Body)
	}
	// The QR is linked to the push the user started.
	var linked interface{}
	for _, call := range api.calls() {
		if call["path"] == "/offline/challenge" {
			linked = call["body"].(map[string]interface{})["requestId"]
		}
	}
	if linked != start.Body.Touchque.RequestID {
		t.Fatalf("QR not linked to the push: %v vs %v", linked, start.Body.Touchque.RequestID)
	}

	// While the QR is up the page keeps polling; nothing changes until the phone answers.
	poll := runGuard(c, GuardInput{User: user, Action: "LOGIN", Token: off.Body.Token})
	if poll.Status != 202 || poll.Body.Touchque.State != StepOffline || poll.Body.Touchque.Offline.ChallengeID != off.Body.Touchque.Offline.ChallengeID {
		t.Fatalf("unexpected poll result: %+v", poll.Body)
	}

	api.reject("") // the user taps Reject on the phone

	rejected := runGuard(c, GuardInput{User: user, Action: "LOGIN", Token: poll.Body.Token})
	if rejected.Status != 403 || rejected.Body.Touchque.State != StepRejected {
		t.Fatalf("expected rejected, got %+v", rejected.Body)
	}
	// Even the right code from the QR already on screen does not finish it...
	late := runGuard(c, GuardInput{User: user, Action: "LOGIN", Token: off.Body.Token, Code: "ABCD123"})
	if late.Approved != nil || late.Body.Touchque.State != StepRejected || late.Body.Touchque.Reason != "request_rejected" {
		t.Fatalf("a rejected sign-in must not be finished by a code: %+v", late)
	}
	// ...nor the time-based code...
	totp := runGuard(c, GuardInput{User: user, Action: "LOGIN", Token: off.Body.Token, Code: "123456", CodeType: "totp"})
	if totp.Approved != nil || totp.Body.Touchque.State != StepRejected {
		t.Fatalf("time-based code must be refused too: %+v", totp)
	}
	// ...and pressing offline mode again gets no QR for that sign-in.
	again := runGuard(c, GuardInput{User: user, Action: "LOGIN", Token: start.Body.Token, Offline: true})
	if again.Body.Touchque.State != StepRejected {
		t.Fatalf("no new QR after a reject: %+v", again.Body)
	}
}

func TestContract_GuardOfflineQRCarriesTheNumberForMatching(t *testing.T) {
	api := startFakeAPI(t)
	c := api.client(t)
	api.link("nm-offline@acme.com")
	api.opts(map[string]interface{}{"numberMatch": true})

	start := runGuard(c, GuardInput{User: "nm-offline@acme.com", Action: "LOGIN"})
	if start.Body.Touchque.Number != "47" {
		t.Fatalf("expected the number on the push step: %+v", start.Body)
	}
	off := runGuard(c, GuardInput{User: "nm-offline@acme.com", Action: "LOGIN", Token: start.Body.Token, Offline: true})
	if off.Body.Touchque.Offline == nil || off.Body.Touchque.Offline.ChallengeCode != "47" {
		t.Fatalf("expected the number for the QR page: %+v", off.Body)
	}
}

func TestContract_GuardFrozenRateLimitedBlocked(t *testing.T) {
	api := startFakeAPI(t)
	api.link("blocked@acme.com")
	c := api.client(t)

	api.opts(map[string]interface{}{"frozen": true})
	frozen := runGuard(c, GuardInput{User: "blocked@acme.com", Action: "LOGIN"})
	if frozen.Status != 423 || frozen.Body.Touchque.RetryAfter != 900 {
		t.Fatalf("unexpected frozen result: %+v", frozen.Body)
	}

	api.opts(map[string]interface{}{"frozen": false, "rateLimited": true})
	limited := runGuard(c, GuardInput{User: "blocked@acme.com", Action: "LOGIN"})
	if limited.Status != 429 {
		t.Fatalf("unexpected limited result: %+v", limited.Body)
	}

	api.opts(map[string]interface{}{"rateLimited": false, "blocked": "geo_policy"})
	blocked := runGuard(c, GuardInput{User: "blocked@acme.com", Action: "LOGIN"})
	if blocked.Status != 403 || blocked.Body.Touchque.State != StepBlocked || blocked.Body.Touchque.Reason != "geo_policy" {
		t.Fatalf("unexpected blocked result: %+v", blocked.Body)
	}
}

// R1-04: the browser can only post behavioural signals with this token.
func TestStart_WaitingStepCarriesTheTelemetryToken(t *testing.T) {
	api := startFakeAPI(t)
	api.link("tel@acme.com")
	c := api.client(t)
	step, err := c.Start("LOGIN", "tel@acme.com", StartOptions{})
	if err != nil || step.TelemetryToken != "" {
		t.Fatalf("no token unless the workspace issues one: %+v %v", step, err)
	}
	api.opts(map[string]interface{}{"telemetry": true})
	step, err = c.Start("LOGIN", "tel@acme.com", StartOptions{})
	if err != nil || step.TelemetryToken != "tt_test" {
		t.Fatalf("expected the telemetry token, got %+v %v", step, err)
	}
}

func TestContract_GuardLogsOnlyThroughConfigLogger(t *testing.T) {
	api := startFakeAPI(t)
	api.link("jane4@acme.com")

	// The default: nothing anywhere, the misconfiguration is the 500 answer.
	silent := runGuard(api.client(t), GuardInput{User: "jane4@acme.com", Action: "NOT_DEFINED"})
	if silent.Status != 500 || silent.Body.Error.Code != "misconfigured" {
		t.Fatalf("unexpected result: %+v", silent)
	}

	var buf bytes.Buffer
	logged := NewClient(&Config{APIKey: "tq_test_key", APISecret: "test_secret", BaseURL: api.baseURL, TimeoutMs: 5000,
		Logger: slog.New(slog.NewTextHandler(&buf, nil))})
	if res := runGuard(logged, GuardInput{User: "jane4@acme.com", Action: "NOT_DEFINED"}); res.Status != 500 {
		t.Fatalf("unexpected result: %+v", res)
	}
	if !strings.Contains(buf.String(), "[Touchque] misconfigured") || !strings.Contains(buf.String(), "NOT_DEFINED") {
		t.Fatalf("expected the misconfiguration in the logger, got %q", buf.String())
	}
}

// ── first-time QR: one QR per enrollment, not one per poll ──────────────

func callPaths(calls []map[string]interface{}) []string {
	paths := make([]string, 0, len(calls))
	for _, call := range calls {
		path, _ := call["path"].(string)
		paths = append(paths, path)
	}
	return paths
}

func TestContract_EnrollPollsKeepTheQRUntilThePhoneIsLinked(t *testing.T) {
	api := startFakeAPI(t)
	c := api.client(t)
	const user = "new-qr@acme.com"
	in := GuardInput{User: user, Action: "LOGIN", Details: []LoginDetail{{Label: "Device", Value: "Mac"}}}

	first := runGuard(c, in)
	qr := first.Body.Touchque.Enroll
	if first.Status != 202 || qr == nil || qr.QRCodeDataURL != "data:image/png;base64,QR-"+user || !reflect.DeepEqual(qr.RecoveryCodes, []string{"r1"}) {
		t.Fatalf("first: status=%d body=%+v", first.Status, first.Body)
	}
	ee, ok := isoMs(qr.ExpiresAt)
	if left := ee - nowMs(); !ok || left <= 290000 || left > 300000 { // the API's own expiresAt (5 minutes)
		t.Fatalf("expiresAt = %q", qr.ExpiresAt)
	}
	if claims := VerifyGuardToken("test_secret", first.Body.Token); claims == nil || claims.St != string(StepEnroll) || claims.Ee != ee {
		t.Fatalf("claims = %+v", claims)
	}

	before := len(api.calls())
	in.Token = first.Body.Token
	poll := runGuard(c, in)
	want := Step{State: StepEnroll, ExpiresAt: qr.ExpiresAt, Details: in.Details}
	if poll.Status != 202 || !reflect.DeepEqual(poll.Body.Touchque, want) {
		t.Fatalf("poll: status=%d step=%+v", poll.Status, poll.Body.Touchque)
	}
	if paths := callPaths(api.calls()[before:]); !reflect.DeepEqual(paths, []string{"/users/" + user}) {
		t.Fatalf("a poll only reads the link state, got %v", paths) // no generate-secret, no reset
	}
	if claims := VerifyGuardToken("test_secret", poll.Body.Token); claims == nil || claims.St != string(StepEnroll) || claims.Ee != ee {
		t.Fatalf("poll claims = %+v", claims)
	}

	api.link(user) // the phone scanned the QR
	in.Token = poll.Body.Token
	if waiting := runGuard(c, in); waiting.Status != 202 || waiting.Body.Touchque.State != StepWaiting {
		t.Fatalf("linked: status=%d body=%+v", waiting.Status, waiting.Body)
	}
}

func TestContract_AnEnrollQRAboutToExpireIsReplaced(t *testing.T) {
	api := startFakeAPI(t)
	api.opts(map[string]interface{}{"secretTtlMs": 1000})
	c := api.client(t)
	const user = "late@acme.com"
	first := runGuard(c, GuardInput{User: user, Action: "LOGIN"})
	if first.Body.Touchque.Enroll == nil || first.Body.Touchque.Enroll.QRCodeDataURL != "data:image/png;base64,QR-"+user {
		t.Fatalf("first: %+v", first.Body)
	}
	poll := runGuard(c, GuardInput{User: user, Action: "LOGIN", Token: first.Body.Token})
	if poll.Status != 202 || poll.Body.Touchque.Enroll == nil || poll.Body.Touchque.Enroll.QRCodeDataURL != "data:image/png;base64,QR2-"+user {
		t.Fatalf("within 15 s of its expiry: status=%d body=%+v", poll.Status, poll.Body)
	}
}

func TestContract_AnEnrollQRThatIsGoneIsReplaced(t *testing.T) {
	api := startFakeAPI(t)
	c := api.client(t)
	const user = "gone@acme.com"
	first := runGuard(c, GuardInput{User: user, Action: "LOGIN"}) // the default 5 minutes: still up
	if ee := VerifyGuardToken("test_secret", first.Body.Token).Ee; ee-nowMs() < 60000 {
		t.Fatalf("the QR should be far from its expiry, ee=%d", ee)
	}
	api.call("/__test/reset", map[string]interface{}{}) // the QR is gone: GET /users answers 404
	before := len(api.calls())
	fresh := runGuard(c, GuardInput{User: user, Action: "LOGIN", Token: first.Body.Token})
	if fresh.Status != 202 || fresh.Body.Touchque.Enroll == nil || fresh.Body.Touchque.Enroll.QRCodeDataURL != "data:image/png;base64,QR-"+user {
		t.Fatalf("gone: status=%d body=%+v", fresh.Status, fresh.Body)
	}
	if paths := callPaths(api.calls()[before:]); !reflect.DeepEqual(paths, []string{"/users/" + user, "/login/request", "/auth/generate-secret"}) {
		t.Fatalf("calls = %v", paths)
	}
}

func TestContract_BeforeStartRunsOnceOnlyWhenAnEnrollTokenStarts(t *testing.T) {
	api := startFakeAPI(t)
	c := api.client(t)
	calls := 0
	hook := func() *GuardResult { calls++; return nil }
	const user = "new-hook@acme.com"
	in := GuardInput{User: user, Action: "LOGIN", BeforeStart: hook}
	first := runGuard(c, in) // a fresh attempt: never
	in.Token = first.Body.Token
	if keep := runGuard(c, in); keep.Body.Touchque.State != StepEnroll || keep.Body.Touchque.Enroll != nil || calls != 0 {
		t.Fatalf("keeping the QR runs no hook: %+v calls=%d", keep.Body, calls)
	}

	api.link(user)
	before := len(api.calls())
	refused := in
	refused.BeforeStart = func() *GuardResult {
		return &GuardResult{Status: 429, Body: &GuardBody{Touchque: Step{State: StepRateLimited, RetryAfter: 60}}}
	}
	if res := runGuard(c, refused); res.Status != 429 || res.Body.Touchque.RetryAfter != 60 {
		t.Fatalf("the hook's answer: status=%d body=%+v", res.Status, res.Body)
	}
	if paths := callPaths(api.calls()[before:]); !reflect.DeepEqual(paths, []string{"/users/" + user}) {
		t.Fatalf("nothing may start after the hook answered: %v", paths)
	}
	if went := runGuard(c, in); went.Body.Touchque.State != StepWaiting || calls != 1 {
		t.Fatalf("linked: %+v calls=%d", went.Body, calls)
	}

	api.opts(map[string]interface{}{"secretTtlMs": 1000}) // within 15 s of its expiry: the hook runs before the new QR
	late := runGuard(c, GuardInput{User: "late-hook@acme.com", Action: "LOGIN"})
	if renewed := runGuard(c, GuardInput{User: "late-hook@acme.com", Action: "LOGIN", Token: late.Body.Token, BeforeStart: hook}); renewed.Body.Touchque.Enroll == nil || calls != 2 {
		t.Fatalf("renewed: %+v calls=%d", renewed.Body, calls)
	}

	api.call("/__test/reset", map[string]interface{}{})
	fresh := runGuard(c, GuardInput{User: "gone-hook@acme.com", Action: "LOGIN"})
	api.call("/__test/reset", map[string]interface{}{}) // the QR is gone (404): the hook runs before the new QR
	if gone := runGuard(c, GuardInput{User: "gone-hook@acme.com", Action: "LOGIN", Token: fresh.Body.Token, BeforeStart: hook}); gone.Body.Touchque.Enroll == nil || calls != 3 {
		t.Fatalf("gone: %+v calls=%d", gone.Body, calls)
	}
}

func TestContract_EnrollLinkCheckErrorIsUnavailable(t *testing.T) {
	api := startFakeAPI(t)
	c := api.client(t)
	first := runGuard(c, GuardInput{User: "down@acme.com", Action: "LOGIN"})
	api.opts(map[string]interface{}{"featureRefused": "feature_off"}) // every signed call answers 403
	down := runGuard(c, GuardInput{User: "down@acme.com", Action: "LOGIN", Token: first.Body.Token})
	if down.Status != 503 || down.Body.Touchque.Reason != "unavailable" {
		t.Fatalf("status=%d body=%+v", down.Status, down.Body)
	}
}

func TestContract_IsStatusPollCountsABoundEnrollToken(t *testing.T) {
	api := startFakeAPI(t)
	c := api.client(t)
	const user = "new-poll@acme.com"
	token := runGuard(c, GuardInput{User: user, Action: "LOGIN"}).Body.Token
	if !IsStatusPoll(c, GuardInput{User: user, Action: "LOGIN", Token: token}) {
		t.Fatal("a bound enroll token with its QR's expiry is a status poll")
	}
	for name, in := range map[string]GuardInput{
		"another user":   {User: "other@acme.com", Action: "LOGIN", Token: token},
		"another action": {User: user, Action: "SEND_MONEY", Token: token},
		"offline":        {User: user, Action: "LOGIN", Token: token, Offline: true},
	} {
		if IsStatusPoll(c, in) {
			t.Errorf("%s: counted as a status poll", name)
		}
	}

	// The poll that renews an expiring QR (or replays an old token) still counts against the limit.
	api.opts(map[string]interface{}{"secretTtlMs": 1000})
	expiring := runGuard(c, GuardInput{User: "late-poll@acme.com", Action: "LOGIN"}).Body.Token
	if claims := VerifyGuardToken("test_secret", expiring); claims == nil || claims.Ee == 0 ||
		IsStatusPoll(c, GuardInput{User: "late-poll@acme.com", Action: "LOGIN", Token: expiring}) {
		t.Fatalf("a QR within 15 s of its expiry is not a status poll: %+v", claims)
	}

	// No expiry (an enroll step without a QR, or a 5.0 token): every poll starts again, as before.
	old := runGuard(c, GuardInput{User: user, Action: "LOGIN", NoEnroll: true})
	if old.Body.Touchque.Enroll != nil || VerifyGuardToken("test_secret", old.Body.Token).Ee != 0 ||
		IsStatusPoll(c, GuardInput{User: user, Action: "LOGIN", Token: old.Body.Token}) {
		t.Fatalf("no expiry: %+v", old.Body)
	}
}
