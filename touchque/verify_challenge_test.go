package touchque

import "testing"

// VerifyWithOptions' OnChallenge against the shared fake TouchQue API: the
// number reaches the caller before the wait (the callback approves, so the
// call could not finish otherwise), and a callback that panics does not stop
// the wait. Same scenarios as the Node SDK.

func TestVerifyOnChallengeGetsTheNumberBeforeTheWait(t *testing.T) {
	api := startFakeAPI(t)
	api.link("jane@acme.com")
	api.opts(map[string]interface{}{"numberMatch": true})
	var seen []VerifyChallenge
	res, err := api.client(t).Login.VerifyWithOptions(LoginRequestOptions{
		ExternalUsername: "jane@acme.com", Type: "LOGIN",
		OnChallenge: func(c VerifyChallenge) { seen = append(seen, c); api.approve(c.RequestID) },
	}, 5000)
	if err != nil || !res.Approved {
		t.Fatalf("res = %+v, err = %v", res, err)
	}
	if len(seen) != 1 || seen[0].RequestID != res.RequestID || seen[0].ChallengeCode != "47" || seen[0].CaseCode != "K7P-2QX" || seen[0].ExpiresAt == "" {
		t.Fatalf("seen = %+v", seen)
	}
	if len(seen[0].Reasons) != 1 || seen[0].Reasons[0].Code != "number_match_requested" {
		t.Fatalf("reasons = %+v", seen[0].Reasons)
	}
}

func TestVerifyKeepsWaitingWhenOnChallengePanics(t *testing.T) {
	api := startFakeAPI(t)
	api.link("jane@acme.com")
	res, err := api.client(t).Login.VerifyWithOptions(LoginRequestOptions{
		ExternalUsername: "jane@acme.com", Type: "SEND_MONEY",
		OnChallenge: func(c VerifyChallenge) { api.approve(c.RequestID); panic("screen gone") },
	}, 5000)
	if err != nil || !res.Approved || res.ChallengeCode != "47" {
		t.Fatalf("res = %+v, err = %v", res, err)
	}
}
