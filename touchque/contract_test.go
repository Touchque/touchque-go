package touchque

// Contract tests against the shared fake TouchQue API — a real HTTP round
// trip, so request signing is verified too (not just mocked). Same
// scenarios as the Node/Python/PHP SDKs' step-up tests.

import (
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
	if _, err := c.Actions.Define("EXPORT", DefineOptions{Name: "Export data", Critical: &critical}); err != nil {
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
