package touchque

import (
	"encoding/json"
	"net/http"
	"testing"
)

func TestOffline_ChallengePostsExpectedFields(t *testing.T) {
	var seenBody map[string]interface{}
	client, closeFn := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&seenBody)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"challengeId": "c1", "qrDataUrl": "data:x"})
	})
	defer closeFn()

	_, err := client.Offline.Challenge(OfflineChallengeOptions{
		ExternalUsername: "a@b.com", Type: "WITHDRAW", TTLSeconds: 60,
		Details: []LoginDetail{{Label: "Amount", Value: "10 EUR"}},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if seenBody["externalUsername"] != "a@b.com" || seenBody["type"] != "WITHDRAW" || seenBody["ttlSeconds"] != float64(60) {
		t.Fatalf("unexpected body: %+v", seenBody)
	}
}

func TestOffline_VerifyReturnsApprovedFalseInsteadOfError(t *testing.T) {
	client, closeFn := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"approved": false, "reason": "invalid_code", "attemptsLeft": float64(3)})
	})
	defer closeFn()

	result, err := client.Offline.Verify("c1", "WRONG12")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Approved || result.Reason != "invalid_code" || result.AttemptsLeft != 3 {
		t.Fatalf("unexpected result: %+v", result)
	}
}

func TestOffline_VerifyPropagatesServerErrors(t *testing.T) {
	client, closeFn := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"error": "boom"})
	})
	defer closeFn()

	_, err := client.Offline.Verify("c1", "AAAA123")
	if _, ok := err.(*APIError); !ok {
		t.Fatalf("expected *APIError, got %T", err)
	}
}
