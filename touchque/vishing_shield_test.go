package touchque

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

// Vishing Shield and Mirror Alarm, against the shared fake API.

func TestShield_FirstWaitingStepCarriesTheCanaryPollsDoNot(t *testing.T) {
	api := startFakeAPI(t)
	api.link("jane@acme.com")
	c := api.client(t)
	if step, err := c.Start("LOGIN", "jane@acme.com", StartOptions{}); err != nil || step.Canary != nil {
		t.Fatalf("no canary unless the API sends one: %+v %v", step, err)
	}
	api.opts(map[string]interface{}{"canary": true})
	first := runGuard(c, GuardInput{User: "jane@acme.com", Action: "LOGIN"})
	if first.Body.Touchque.Canary == nil || !strings.HasSuffix(first.Body.Touchque.Canary.URL, ".gif") {
		t.Fatalf("expected the canary on the first step: %+v", first.Body.Touchque)
	}
	poll := runGuard(c, GuardInput{User: "jane@acme.com", Action: "LOGIN", Token: first.Body.Token})
	if poll.Body.Touchque.State != StepWaiting || poll.Body.Touchque.Canary != nil {
		t.Fatalf("a poll carries no canary: %+v", poll.Body.Touchque)
	}
}

func TestShield_PushTappedDuringACallBecomesPasskeyRequiredAlsoFromTheOfflineQR(t *testing.T) {
	api := startFakeAPI(t)
	api.link("jane@acme.com")
	c := api.client(t)
	first := runGuard(c, GuardInput{User: "jane@acme.com", Action: "LOGIN"})
	rid := first.Body.Touchque.RequestID
	off := runGuard(c, GuardInput{User: "jane@acme.com", Action: "LOGIN", Token: first.Body.Token, Offline: true})
	if off.Body.Touchque.State != StepOffline {
		t.Fatalf("expected the offline QR: %+v", off.Body.Touchque)
	}
	api.escalate(rid)
	poll := runGuard(c, GuardInput{User: "jane@acme.com", Action: "LOGIN", Token: off.Body.Token})
	if poll.Status != 202 || poll.Body.Touchque.State != StepPasskeyRequired || poll.Body.Touchque.RequestID != rid {
		t.Fatalf("expected passkey_required: status=%d %+v", poll.Status, poll.Body.Touchque)
	}
	typed := runGuard(c, GuardInput{User: "jane@acme.com", Action: "LOGIN", Token: off.Body.Token, Code: "ABCD123"})
	if typed.Body.Touchque.State != StepPasskeyRequired {
		t.Fatalf("a refused code says passkey: %+v", typed.Body.Touchque)
	}
}

func TestShield_ProvisionalApprovalAndTheCriticalActionLock(t *testing.T) {
	api := startFakeAPI(t)
	api.link("jane@acme.com")
	c := api.client(t)
	step, _ := c.Start("LOGIN", "jane@acme.com", StartOptions{})
	api.approveProvisional(step.RequestID)
	approval, err := c.Complete(step.RequestID, "jane@acme.com", "LOGIN", CompleteExpect{})
	if err != nil || !approval.Provisional || approval.Revoked {
		t.Fatalf("expected a provisional approval: %+v %v", approval, err)
	}
	locked, err := c.Start("SEND_MONEY", "jane@acme.com", StartOptions{})
	if err != nil || locked.State != StepBlocked || locked.Reason != "provisional" {
		t.Fatalf("expected blocked/provisional: %+v %v", locked, err)
	}
	api.reconfirm(step.RequestID)
	if s, err := c.Start("SEND_MONEY", "jane@acme.com", StartOptions{}); err != nil || s.State != StepWaiting {
		t.Fatalf("expected the lock lifted: %+v %v", s, err)
	}
}

func TestShield_AnApprovalTakenBackIsNeverUsed(t *testing.T) {
	api := startFakeAPI(t)
	api.link("jane@acme.com")
	c := api.client(t)
	first := runGuard(c, GuardInput{User: "jane@acme.com", Action: "LOGIN"})
	api.approve(first.Body.Touchque.RequestID)
	api.revoke(first.Body.Touchque.RequestID, "COACHED")
	done := runGuard(c, GuardInput{User: "jane@acme.com", Action: "LOGIN", Token: first.Body.Token})
	if done.Status != 408 || done.Body.Touchque.State != StepExpired || done.Body.Touchque.Reason != "revoked" {
		t.Fatalf("expected expired/revoked: status=%d %+v", done.Status, done.Body.Touchque)
	}
}

func TestShield_VerifyReturnsPasskeyRequiredWhenTheRequestMovesToAPasskey(t *testing.T) {
	polls := 0
	client, closeFn := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"requestId": "req_1"})
			return
		}
		polls++
		if polls == 1 {
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"status": "PENDING"})
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"status": "PENDING", "requiresPasskey": true})
	})
	defer closeFn()

	_, err := client.Login.Verify("a@b.com", "LOGIN", "", "", "", false, false, 30000)
	pk, ok := err.(*PasskeyRequiredError)
	if !ok || pk.RequestID != "req_1" || pk.Reason != "step_up" {
		t.Fatalf("expected *PasskeyRequiredError step_up, got %T (%v)", err, err)
	}
}

func TestShield_WebhookConstants(t *testing.T) {
	if ReasonVishingSuspected != "vishing_suspected" || ReasonPhishingOrigin != "phishing_origin" || ReasonUserReportedCoached != "user_reported_coached" {
		t.Fatal("reason constants")
	}
	if EventApprovalRevoked != "APPROVAL_REVOKED" || EventApprovalReconfirmed != "APPROVAL_RECONFIRMED" {
		t.Fatal("event constants")
	}
}
