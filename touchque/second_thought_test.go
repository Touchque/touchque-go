package touchque

import (
	"reflect"
	"testing"
	"time"
)

func TestSecondThoughtAndALookAlikeDestination(t *testing.T) {
	f := startFakeAPI(t)
	defer f.close()
	c := f.client(t)

	at, err := c.ActionTypes.Define("PAYOUT", DefineOptions{Name: "Payout", SecondThought: &SecondThought{Questions: []string{"someone_guiding", "safe_account"}, Locale: "en"}})
	if err != nil {
		t.Fatal(err)
	}
	if at.SecondThought == nil || !reflect.DeepEqual(at.SecondThought.Questions, []string{"someone_guiding", "safe_account"}) || at.SecondThought.Locale != "en" {
		t.Fatalf("secondThought = %+v", at.SecondThought)
	}
	if _, err := c.ActionTypes.Define("PAYOUT", DefineOptions{Name: "Payout"}); err != nil {
		t.Fatal(err)
	}
	calls := f.calls()
	if _, sent := calls[len(calls)-1]["body"].(map[string]interface{})["secondThought"]; sent {
		t.Fatal("secondThought sent although it was not set")
	}
	off, err := c.ActionTypes.Define("PAYOUT", DefineOptions{Name: "Payout", SecondThought: &SecondThought{}})
	if err != nil {
		t.Fatal(err)
	}
	if off.SecondThought != nil {
		t.Fatalf("questions not turned off: %+v", off.SecondThought)
	}

	f.link("payee@example.com")
	r, err := c.Login.RequestWithOptions(LoginRequestOptions{
		ExternalUsername: "payee@example.com",
		SecurityChanges:  &SecurityChanges{MFA: time.Date(2026, 10, 26, 8, 0, 0, 0, time.UTC)},
		Destination:      &Destination{Kind: "iban", Value: "TR33 0006 1005 1978 6000 0013 26", Known: []string{"TR33 0006 1005 1978 6457 8413 26"}},
		Locale:           "en",
	})
	if err != nil {
		t.Fatal(err)
	}
	want := &DestinationCheck{Known: false, Lookalike: []DestinationLookalike{{Field: "iban", Reason: "same_start_and_end", SimilarTo: "TR33…1326"}}}
	if !reflect.DeepEqual(r.Destination, want) {
		t.Fatalf("destination = %+v", r.Destination)
	}
	calls = f.calls()
	body := calls[len(calls)-1]["body"].(map[string]interface{})
	if !reflect.DeepEqual(body["securityChanges"], map[string]interface{}{"mfa": "2026-10-26T08:00:00Z"}) || body["locale"] != "en" {
		t.Fatalf("body = %v", body)
	}
}
