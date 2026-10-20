package touchque

import (
	"context"
	"errors"
	"testing"
)

// "Why?" case codes against the shared fake TouchQue API: every decision names
// one, the step shows it with plain reasons, a refusal and the raw API error
// carry it, and the silent check returns it. Same scenarios as the Node SDK.

func TestCaseCodeOnANumberMatchedStep(t *testing.T) {
	api := startFakeAPI(t)
	api.link("jane@acme.com")
	api.opts(map[string]interface{}{"numberMatch": true})
	step, err := api.client(t).Start("LOGIN", "jane@acme.com", StartOptions{})
	if err != nil || step.State != StepWaiting || step.CaseCode != "K7P-2QX" {
		t.Fatalf("step = %+v, err = %v", step, err)
	}
	if len(step.Reasons) != 1 || step.Reasons[0].Code != "number_match_requested" || step.Reasons[0].Text == "" {
		t.Fatalf("reasons = %+v", step.Reasons)
	}
}

func TestCaseCodeOnARefusalStepAndError(t *testing.T) {
	api := startFakeAPI(t)
	api.link("jane@acme.com")
	api.opts(map[string]interface{}{"blocked": "access_policy"})
	c := api.client(t)
	step, err := c.Start("LOGIN", "jane@acme.com", StartOptions{})
	if err != nil || step.State != StepBlocked || step.Reason != "access_policy" || step.CaseCode != "REF-USE" {
		t.Fatalf("step = %+v, err = %v", step, err)
	}
	_, err = c.Login.Request("jane@acme.com", "LOGIN", "", "", "", false, false)
	var apiErr *APIError
	if !errors.As(err, &apiErr) || apiErr.StatusCode != 403 || apiErr.CaseCode != "REF-USE" {
		t.Fatalf("err = %#v", err)
	}
}

func TestCaseCodeOnTheSilentCheck(t *testing.T) {
	api := startFakeAPI(t)
	api.link("jane@acme.com")
	res, err := api.client(t).Risk.Check(context.Background(), RiskCheckOptions{ExternalUsername: "jane@acme.com"})
	if err != nil || res.CaseCode != "CHK-2QX" {
		t.Fatalf("res = %+v, err = %v", res, err)
	}
}

func TestCaseCodeStaysWhileTheGuardWaits(t *testing.T) {
	api := startFakeAPI(t)
	api.link("jane@acme.com")
	api.opts(map[string]interface{}{"numberMatch": true})
	c := api.client(t)
	first := runGuard(c, GuardInput{User: "jane@acme.com", Action: "LOGIN"})
	again := runGuard(c, GuardInput{User: "jane@acme.com", Action: "LOGIN", Token: first.Body.Token})
	if first.Body.Touchque.CaseCode != "K7P-2QX" || again.Body.Touchque.State != StepWaiting || again.Body.Touchque.CaseCode != "K7P-2QX" {
		t.Fatalf("first = %+v, again = %+v", first.Body.Touchque, again.Body.Touchque)
	}
}
