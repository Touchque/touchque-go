package touchque

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"sync/atomic"
	"testing"
	"time"
)

// Login.WaitForApproval polls a request already sent, like the Node SDK's
// login.waitForApproval: the approval, or the error that ended it.

func TestLogin_WaitForApprovalPollsUntilConfirmed(t *testing.T) {
	var polls int32
	client, closeFn := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/login/status/req_1" {
			t.Errorf("unexpected %s %s", r.Method, r.URL.Path)
		}
		if atomic.AddInt32(&polls, 1) < 3 {
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"status": "PENDING"})
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"status": "CONFIRMED", "confirmedVia": "DEVICE", "provisional": true,
			"assurance": map[string]interface{}{"phishingResistant": false, "method": "push"},
		})
	})
	defer closeFn()

	resp, err := client.Login.WaitForApproval(context.Background(), "req_1", 5*time.Second, 10*time.Millisecond)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !resp.Approved || resp.Status != "CONFIRMED" || resp.RequestID != "req_1" || resp.ConfirmedVia != "DEVICE" ||
		!resp.Provisional || resp.Assurance == nil || resp.Assurance.Method != "push" || atomic.LoadInt32(&polls) != 3 {
		t.Fatalf("unexpected response after %d polls: %+v", polls, resp)
	}
}

func TestLogin_WaitForApprovalEndsOnTheAnswer(t *testing.T) {
	for _, c := range []struct {
		name   string
		status map[string]interface{}
		check  func(error) bool
	}{
		{"rejected", map[string]interface{}{"status": "REJECTED"}, func(err error) bool { _, ok := err.(*RejectedError); return ok }},
		{"expired", map[string]interface{}{"status": "EXPIRED"}, func(err error) bool { _, ok := err.(*TimeoutError); return ok }},
		{"moved to a passkey", map[string]interface{}{"status": "PENDING", "requiresPasskey": true}, func(err error) bool {
			pk, ok := err.(*PasskeyRequiredError)
			return ok && pk.RequestID == "req_1" && pk.Reason == "step_up"
		}},
	} {
		client, closeFn := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
			_ = json.NewEncoder(w).Encode(c.status)
		})
		resp, err := client.Login.WaitForApproval(context.Background(), "req_1", 5*time.Second, 10*time.Millisecond)
		closeFn()
		if resp != nil || !c.check(err) {
			t.Errorf("%s: got %+v, %T (%v)", c.name, resp, err, err)
		}
	}
}

func TestLogin_WaitForApprovalTimesOutOrStopsWithTheContext(t *testing.T) {
	client, closeFn := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"status": "PENDING"})
	})
	defer closeFn()

	if _, err := client.Login.WaitForApproval(context.Background(), "req_1", 30*time.Millisecond, 10*time.Millisecond); err == nil {
		t.Fatal("expected a timeout")
	} else if _, ok := err.(*TimeoutError); !ok {
		t.Fatalf("expected *TimeoutError, got %T (%v)", err, err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, err := client.Login.WaitForApproval(ctx, "req_1", time.Minute, 10*time.Second)
	if !errors.Is(err, context.DeadlineExceeded) || time.Since(start) > 5*time.Second {
		t.Fatalf("expected the context's deadline, got %T (%v) after %s", err, err, time.Since(start))
	}
}
