package touchque

import (
	"context"
	"errors"
	"testing"
)

// The help desk against the shared fake API: a passed check used once for its
// own action, a wrong number, "this isn't me" and unfreeze, and no phone.
// Same scenarios as the Node SDK's Assist tests.

func TestAssistPassedCheckIsUsedOnceForItsAction(t *testing.T) {
	api := startFakeAPI(t)
	api.link("ayse@acme.com")
	tq := api.client(t)
	ctx := context.Background()
	s, err := tq.Assist.Open(ctx, OpenAssistOptions{ExternalUsername: "ayse@acme.com", Agent: AssistAgent{Name: "Deniz Kaya", Title: "IT help desk"}, Reason: "Ticket 4411"})
	if err != nil || s.Status != "OPEN" || !s.Notified || !s.Phone || s.Agent.Title != "IT help desk" {
		t.Fatalf("open = %+v, %v", s, err)
	}
	check, err := tq.Assist.Verify(ctx, s.ID, VerifyAssistOptions{Action: "reset_2fa", ActionText: "reset your two-step verification"})
	if err != nil || len(check.ChallengeCode) != 2 {
		t.Fatalf("verify = %+v, %v", check, err)
	}
	api.call("/__test/assist", map[string]interface{}{"requestId": check.RequestID, "action": "approve"})
	now, _ := tq.Assist.Get(ctx, s.ID)
	if !now.CheckPassed(check.RequestID) {
		t.Fatalf("checks = %+v", now.Checks)
	}
	var apiErr *APIError
	if _, err := tq.Assist.Spend(ctx, s.ID, check.RequestID, "reset_password"); !errors.As(err, &apiErr) || apiErr.StatusCode != 428 {
		t.Fatalf("spend for another action = %v", err)
	}
	spent, err := tq.Assist.Spend(ctx, s.ID, check.RequestID, "reset_2fa")
	if err != nil || spent.CheckPassed(check.RequestID) {
		t.Fatalf("spend = %+v, %v", spent, err)
	}
	if list, err := tq.Assist.List(ctx, "ayse@acme.com", false); err != nil || list[0].ID != s.ID {
		t.Fatalf("list = %+v, %v", list, err)
	}
	if ended, err := tq.Assist.End(ctx, s.ID, "", ""); err != nil || ended.Status != "ENDED" {
		t.Fatalf("end = %+v, %v", ended, err)
	}
	if _, err := tq.Assist.Verify(ctx, s.ID, VerifyAssistOptions{Action: "unlock"}); !errors.As(err, &apiErr) || apiErr.Code != "assist_not_open" {
		t.Fatalf("verify after end = %v", err)
	}
}

func TestAssistWrongNumberNotMeAndUnfreeze(t *testing.T) {
	api := startFakeAPI(t)
	api.link("ayse@acme.com")
	tq := api.client(t)
	ctx := context.Background()
	s, _ := tq.Assist.Open(ctx, OpenAssistOptions{ExternalUsername: "ayse@acme.com", Agent: AssistAgent{Name: "Deniz Kaya"}, NoNotice: true})
	bad, _ := tq.Assist.Verify(ctx, s.ID, VerifyAssistOptions{Action: "activation_link"})
	api.call("/__test/assist", map[string]interface{}{"requestId": bad.RequestID, "action": "wrong_number"})
	var apiErr *APIError
	if _, err := tq.Assist.Spend(ctx, s.ID, bad.RequestID, "activation_link"); !errors.As(err, &apiErr) || apiErr.Code != "check_required" {
		t.Fatalf("spend after wrong number = %v", err)
	}
	notMe, _ := tq.Assist.Verify(ctx, s.ID, VerifyAssistOptions{Action: "activation_link"})
	api.call("/__test/assist", map[string]interface{}{"requestId": notMe.RequestID, "action": "not_me"})
	if now, _ := tq.Assist.Get(ctx, s.ID); !now.Frozen || now.Checks[1].Outcome != "not_me" || now.Notified {
		t.Fatalf("after not_me = %+v", now)
	}
	unlock, _ := tq.Assist.Verify(ctx, s.ID, VerifyAssistOptions{Action: "unlock"})
	api.call("/__test/assist", map[string]interface{}{"requestId": unlock.RequestID, "action": "approve"})
	unfrozen, after, err := tq.Assist.Unfreeze(ctx, s.ID, unlock.RequestID)
	if err != nil || !unfrozen || after.Frozen {
		t.Fatalf("unfreeze = %v %+v %v", unfrozen, after, err)
	}
}

func TestAssistNoPhoneRoutesToNeverLockedOut(t *testing.T) {
	api := startFakeAPI(t)
	tq := api.client(t)
	ctx := context.Background()
	if _, err := tq.Auth.GenerateSecret("can@acme.com"); err != nil {
		t.Fatal(err)
	}
	s, err := tq.Assist.Open(ctx, OpenAssistOptions{ExternalUsername: "can@acme.com", Agent: AssistAgent{Name: "Deniz Kaya"}})
	if err != nil || s.Phone {
		t.Fatalf("open = %+v, %v", s, err)
	}
	var apiErr *APIError
	if _, err := tq.Assist.Verify(ctx, s.ID, VerifyAssistOptions{Action: "new_phone"}); !errors.As(err, &apiErr) || apiErr.Code != "no_phone" || apiErr.Data["route"] != "never_locked_out" {
		t.Fatalf("verify = %v", err)
	}
	if _, err := tq.Assist.Open(ctx, OpenAssistOptions{ExternalUsername: "can@acme.com"}); err == nil {
		t.Fatal("open without an agent should fail")
	}
}
