package touchque

import "testing"

// VerifyApprovalProof against the cross-SDK golden vectors
// (fixtures/approval-proof-vectors.json, shared with Node, Python and PHP).

type proofVectors struct {
	DigestCases []struct {
		Details []LoginDetail `json:"details"`
		// details_object cases need ordered keys, which a Go map can't keep:
		// Go callers pass []LoginDetail, so those cases are skipped here.
		DetailsObject map[string]string `json:"details_object"`
		Digest        string            `json:"digest"`
	} `json:"digest_cases"`
	Cases []struct {
		Name    string      `json:"name"`
		Proof   interface{} `json:"proof"`
		Options struct {
			RequestID         string        `json:"requestId"`
			Type              string        `json:"type"`
			Details           []LoginDetail `json:"details"`
			ChallengeCode     string        `json:"challengeCode"`
			ExpectedPublicKey string        `json:"expectedPublicKey"`
			AllowUnpinnedKey  bool          `json:"allowUnpinnedKey"`
		} `json:"options"`
		Expected bool `json:"expected"`
	} `json:"cases"`
}

func TestApprovalProofVectors(t *testing.T) {
	var v proofVectors
	readFixture(t, "approval-proof-vectors.json", &v)
	for _, c := range v.DigestCases {
		if c.DetailsObject != nil {
			continue
		}
		if got := DetailsDigest(c.Details); got != c.Digest {
			t.Errorf("DetailsDigest(%v) = %q, want %q", c.Details, got, c.Digest)
		}
	}
	if len(v.Cases) == 0 {
		t.Fatal("no cases in fixture")
	}
	for _, c := range v.Cases {
		o := c.Options
		got := VerifyApprovalProof(c.Proof, VerifyApprovalProofOptions{
			RequestID: o.RequestID, Type: o.Type, Details: o.Details, ChallengeCode: o.ChallengeCode,
			ExpectedPublicKey: o.ExpectedPublicKey, AllowUnpinnedKey: o.AllowUnpinnedKey,
		})
		if got != c.Expected {
			t.Errorf("%s: got %v, want %v", c.Name, got, c.Expected)
		}
	}
}

func TestApprovalProofGarbageIsFalse(t *testing.T) {
	opts := VerifyApprovalProofOptions{RequestID: "r", Type: "t", AllowUnpinnedKey: true}
	for _, p := range []interface{}{nil, (*ApprovalProof)(nil), "x", 42, []byte("{"), map[string]interface{}{"version": "v2"},
		map[string]interface{}{"version": "v2", "algorithm": "ECDSA-P256-SHA256", "message": 1, "signature": nil}} {
		if VerifyApprovalProof(p, opts) {
			t.Errorf("garbage %#v verified", p)
		}
	}
}
