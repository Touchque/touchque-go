package touchque

// Safe Guard: the verifier against the shared vectors
// (fixtures/safe-guard-vectors.json, derived from the reference project and
// shared with every server SDK), and Request / Status / WaitForApproval
// against the shared fake Touchque API.

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

type safeVector struct {
	Name           string           `json:"name"`
	SafeTx         SafeGuardTx      `json:"safeTx"`
	Class          string           `json:"class"`
	Purpose        string           `json:"purpose"`
	SafeTxHash     string           `json:"safeTxHash"`
	GovernanceHash string           `json:"governanceHash"`
	Subject        string           `json:"subject"`
	ExpiresAt      uint64           `json:"expiresAt"`
	DisplayDigest  string           `json:"displayDigest"`
	Message        string           `json:"message"`
	Approval       string           `json:"approval"`
	Rows           []SafeDisplayRow `json:"rows"`
	RowsDigest     string           `json:"rowsDigest"`
}

type safeVectors struct {
	ApproverKey string       `json:"approverKey"`
	Now         int64        `json:"now"`
	Vectors     []safeVector `json:"vectors"`
	Checks      []struct {
		Name     string `json:"name"`
		Vector   string `json:"vector"`
		Approval string `json:"approval"`
		Options  struct {
			Purpose       string `json:"purpose"`
			ApproverIndex *int   `json:"approverIndex"`
			DisplayDigest string `json:"displayDigest"`
			Now           *int64 `json:"now"`
		} `json:"options"`
		Reason  *string `json:"reason"`
		Purpose string  `json:"purpose"`
		Key     string  `json:"key"`
	} `json:"checks"`
	WithApprovals struct {
		OwnerSignatures string   `json:"ownerSignatures"`
		Approvals       []string `json:"approvals"`
		Expected        string   `json:"expected"`
	} `json:"withApprovals"`
	ScheduleCall struct {
		Safe           string   `json:"safe"`
		GovernanceHash string   `json:"governanceHash"`
		Approvals      []string `json:"approvals"`
		Expected       string   `json:"expected"`
	} `json:"scheduleCall"`
}

func loadSafeVectors(t *testing.T) safeVectors {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "fixtures", "safe-guard-vectors.json"))
	if err != nil {
		t.Fatal(err)
	}
	var v safeVectors
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	return v
}

func (v safeVectors) vector(name string) safeVector {
	for _, x := range v.Vectors {
		if x.Name == name {
			return x
		}
	}
	return safeVector{}
}

func TestSafeGuardVectors(t *testing.T) {
	vs := loadSafeVectors(t)
	now := time.Unix(vs.Now, 0)
	for _, v := range vs.Vectors {
		t.Run(v.Name, func(t *testing.T) {
			target := v.SafeTx.SafeTxTarget
			if h, err := SafeTxHash(target); err != nil || h != v.SafeTxHash {
				t.Fatalf("SafeTxHash = %s, %v", h, err)
			}
			if h, err := SafeGovernanceHash(target); err != nil || h != v.GovernanceHash {
				t.Fatalf("SafeGovernanceHash = %s, %v", h, err)
			}
			m, err := SafeApprovalMessage(SafeApprovalMessageFields{Purpose: v.Purpose, ChainID: target.ChainID, Guard: target.Guard, Safe: target.Safe, Subject: v.Subject, ExpiresAt: v.ExpiresAt, DisplayDigest: v.DisplayDigest})
			if err != nil || m != v.Message {
				t.Fatalf("SafeApprovalMessage = %s, %v", m, err)
			}
			if v.Rows != nil && SafeDisplayDigest(v.Rows) != v.RowsDigest {
				t.Fatalf("SafeDisplayDigest = %s", SafeDisplayDigest(v.Rows))
			}
			index := v.SafeTx.ApproverIndex
			got, err := VerifySafeApproval(target, v.Approval, vs.ApproverKey, VerifySafeApprovalOptions{Purpose: v.Purpose, Now: now, ApproverIndex: &index})
			want := SafeApprovalVerification{Valid: true, Purpose: v.Purpose, ApproverIndex: index, ExpiresAt: v.ExpiresAt, DisplayDigest: v.DisplayDigest, SafeTxHash: v.SafeTxHash, GovernanceHash: v.GovernanceHash}
			if err != nil || *got != want {
				t.Fatalf("VerifySafeApproval = %+v, %v", got, err)
			}
		})
	}
	for _, c := range vs.Checks {
		t.Run("check: "+c.Name, func(t *testing.T) {
			key := vs.ApproverKey
			if c.Key != "" {
				key = c.Key
			}
			at := now
			if c.Options.Now != nil {
				at = time.Unix(*c.Options.Now, 0)
			}
			got, err := VerifySafeApproval(vs.vector(c.Vector).SafeTx.SafeTxTarget, c.Approval, key, VerifySafeApprovalOptions{
				Purpose: c.Options.Purpose, ApproverIndex: c.Options.ApproverIndex, DisplayDigest: c.Options.DisplayDigest, Now: at,
			})
			want := ""
			if c.Reason != nil {
				want = *c.Reason
			}
			if err != nil || got.Reason != want || got.Valid != (want == "") || (c.Purpose != "" && got.Purpose != c.Purpose) {
				t.Fatalf("got %+v, %v; want reason %q", got, err, want)
			}
		})
	}
	if got, err := WithSafeApprovals(vs.WithApprovals.OwnerSignatures, vs.WithApprovals.Approvals); err != nil || got != vs.WithApprovals.Expected {
		t.Fatalf("WithSafeApprovals = %s, %v", got, err)
	}
	s := vs.ScheduleCall
	if got, err := SafeScheduleCall(s.Safe, s.GovernanceHash, s.Approvals); err != nil || got != s.Expected {
		t.Fatalf("SafeScheduleCall = %s, %v", got, err)
	}
	bad := vs.Vectors[0].SafeTx.SafeTxTarget
	bad.Tx.Operation = 2
	var cfg *ConfigError
	if _, err := SafeTxHash(bad); !errors.As(err, &cfg) {
		t.Fatalf("operation 2: %v", err)
	}
}

func TestSafeGuardAgainstTheFakeAPI(t *testing.T) {
	api := startFakeAPI(t)
	defer api.close()
	vs := loadSafeVectors(t)
	v := vs.vector("bybit_pattern")
	api.link("treasurer@acme.com")
	api.opts(map[string]interface{}{"safeTxView": map[string]interface{}{"class": v.Class, "flags": []string{"delegatecall"}, "safeTxHash": v.SafeTxHash, "governanceHash": v.GovernanceHash, "purpose": v.Purpose}})
	client := NewClient(&Config{APIKey: "tq_test_key", APISecret: "test_secret", BaseURL: api.baseURL})
	ctx := context.Background()

	sent, err := client.SafeGuard.Request(ctx, SafeGuardRequestOptions{ExternalUsername: "treasurer@acme.com", Type: "safe_payment", SafeTx: v.SafeTx, ReferenceID: "tx-1"})
	if err != nil || sent.SafeTx.GovernanceHash == nil || *sent.SafeTx.GovernanceHash != v.GovernanceHash {
		t.Fatalf("Request = %+v, %v", sent, err)
	}
	calls := api.calls()
	body := calls[len(calls)-1]["body"].(map[string]interface{})
	safeTx := body["safeTx"].(map[string]interface{})
	if calls[len(calls)-1]["path"] != "/safe-guard/approvals" || body["referenceId"] != "tx-1" || safeTx["chainId"] != "1" || safeTx["tx"].(map[string]interface{})["nonce"] != v.SafeTx.Tx.Nonce {
		t.Fatalf("sent %v", calls[len(calls)-1])
	}
	if st, err := client.SafeGuard.Status(ctx, sent.RequestID); err != nil || st.SafeTx.Approval != "" {
		t.Fatalf("Status before approval = %+v, %v", st, err)
	}

	api.call("/__test/approve", map[string]interface{}{"id": sent.RequestID, "safeTx": map[string]interface{}{"approval": v.Approval, "expiresAt": v.ExpiresAt}})
	done, err := client.SafeGuard.WaitForApproval(ctx, sent.RequestID, 5*time.Second, 10*time.Millisecond)
	if err != nil || done.Status != "CONFIRMED" {
		t.Fatalf("WaitForApproval = %+v, %v", done, err)
	}
	index := done.SafeTx.ApproverIndex
	// A governance change is checked with its purpose named, as the README does.
	check, err := VerifySafeApproval(v.SafeTx.SafeTxTarget, done.SafeTx.Approval, vs.ApproverKey, VerifySafeApprovalOptions{Purpose: done.SafeTx.Purpose, Now: time.Unix(vs.Now, 0), ApproverIndex: &index})
	if err != nil || !check.Valid || check.Purpose != "schedule" {
		t.Fatalf("VerifySafeApproval = %+v, %v", check, err)
	}

	again, err := client.SafeGuard.Request(ctx, SafeGuardRequestOptions{ExternalUsername: "treasurer@acme.com", Type: "safe_payment", SafeTx: v.SafeTx})
	if err != nil {
		t.Fatal(err)
	}
	api.reject(again.RequestID)
	var rejected *RejectedError
	if _, err := client.SafeGuard.WaitForApproval(ctx, again.RequestID, 5*time.Second, 10*time.Millisecond); !errors.As(err, &rejected) {
		t.Fatalf("after a refusal: %v", err)
	}
}
