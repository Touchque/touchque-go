package touchque

import (
	"encoding/json"
	"net/http"
	"testing"
)

func TestLogin_Request(t *testing.T) {
	var seenPath string
	client, closeFn := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		seenPath = r.URL.Path
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"requestId": "req_1", "message": "ok", "expiresAt": "t"})
	})
	defer closeFn()

	resp, err := client.Login.Request("a@b.com", "LOGIN", "", "", "", false, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if seenPath != "/login/request" {
		t.Fatalf("expected /login/request, got %s", seenPath)
	}
	if resp.RequestID != "req_1" {
		t.Fatalf("unexpected response: %+v", resp)
	}
}

func TestLogin_Status(t *testing.T) {
	client, closeFn := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/login/status/req_1" {
			t.Errorf("expected /login/status/req_1, got %s", r.URL.Path)
		}
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"status": "PENDING"})
	})
	defer closeFn()

	resp, err := client.Login.Status("req_1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.Status != "PENDING" {
		t.Fatalf("unexpected response: %+v", resp)
	}
}

func TestLogin_VerifyReturnsApprovedOnFirstPoll(t *testing.T) {
	client, closeFn := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"requestId": "req_1"})
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"status": "CONFIRMED"})
	})
	defer closeFn()

	resp, err := client.Login.Verify("a@b.com", "LOGIN", "", "", "", false, false, 30000)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !resp.Approved || resp.Status != "CONFIRMED" {
		t.Fatalf("unexpected response: %+v", resp)
	}
}

func TestLogin_VerifyReturnsRejectedErrorOnFirstPoll(t *testing.T) {
	client, closeFn := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"requestId": "req_1"})
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"status": "REJECTED"})
	})
	defer closeFn()

	_, err := client.Login.Verify("a@b.com", "LOGIN", "", "", "", false, false, 30000)
	if _, ok := err.(*RejectedError); !ok {
		t.Fatalf("expected *RejectedError, got %T (%v)", err, err)
	}
}

func TestLogin_VerifyReturnsTimeoutErrorImmediatelyWhenBudgetIsZero(t *testing.T) {
	// timeoutMs=0 means the very first elapsed-time check (after the first
	// status poll) already exceeds the budget, so this returns before ever
	// calling the real time.Sleep(400ms) — keeps the test fast.
	client, closeFn := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"requestId": "req_1"})
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"status": "PENDING"})
	})
	defer closeFn()

	_, err := client.Login.Verify("a@b.com", "LOGIN", "", "", "", false, false, 0)
	if _, ok := err.(*TimeoutError); !ok {
		t.Fatalf("expected *TimeoutError, got %T (%v)", err, err)
	}
}

func TestLogin_ApproveWithRecoveryCode(t *testing.T) {
	client, closeFn := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/login/recovery" {
			t.Errorf("expected /login/recovery, got %s", r.URL.Path)
		}
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"success": true, "message": "approved"})
	})
	defer closeFn()

	resp, err := client.Login.ApproveWithRecoveryCode("req_1", "ABCD-1234")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Regression test for the bug fixed alongside this test suite: `success`
	// is a real JSON boolean, not a string.
	if !resp.Success {
		t.Fatalf("expected Success=true, got %+v", resp)
	}
}

func TestLogin_RequestWithOptions_SendsDetailsInOrder(t *testing.T) {
	var body map[string]interface{}
	client, closeFn := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&body)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"requestId": "req_1", "message": "ok", "expiresAt": "t"})
	})
	defer closeFn()

	_, err := client.Login.RequestWithOptions(LoginRequestOptions{
		ExternalUsername: "a@b.com",
		Type:             "WITHDRAW",
		ClientIP:         "203.0.113.7",
		Details:          []LoginDetail{{Label: "Amount", Value: "1,250.00 USD"}, {Label: "Recipient", Value: "Jane Doe"}},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	details, ok := body["details"].([]interface{})
	if !ok || len(details) != 2 {
		t.Fatalf("expected 2 details, got %#v", body["details"])
	}
	first := details[0].(map[string]interface{})
	if first["label"] != "Amount" || first["value"] != "1,250.00 USD" || body["clientIp"] != "203.0.113.7" || body["type"] != "WITHDRAW" {
		t.Fatalf("unexpected payload: %#v", body)
	}
}

func TestLogin_Request_OmitsDetailsWhenNone(t *testing.T) {
	var body map[string]interface{}
	client, closeFn := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&body)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"requestId": "req_1"})
	})
	defer closeFn()

	if _, err := client.Login.Request("a@b.com", "LOGIN", "", "", "", false, false); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, present := body["details"]; present {
		t.Fatalf("details must be omitted when empty: %#v", body)
	}
}

func TestLogin_VerifyReturnsTimeoutErrorWhenExpired(t *testing.T) {
	client, closeFn := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"requestId": "req_1"})
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"status": "EXPIRED"})
	})
	defer closeFn()

	_, err := client.Login.Verify("a@b.com", "LOGIN", "", "", "", false, false, 30000)
	if _, ok := err.(*TimeoutError); !ok {
		t.Fatalf("expected *TimeoutError, got %T (%v)", err, err)
	}
}

func TestLogin_VerifyReturnsPasskeyRequiredErrorWithoutPolling(t *testing.T) {
	polled := false
	client, closeFn := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"requestId": "req_1", "requiresPasskey": true})
			return
		}
		polled = true
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"status": "PENDING"})
	})
	defer closeFn()

	_, err := client.Login.Verify("a@b.com", "LOGIN", "", "", "", false, false, 30000)
	pkErr, ok := err.(*PasskeyRequiredError)
	if !ok {
		t.Fatalf("expected *PasskeyRequiredError, got %T (%v)", err, err)
	}
	if pkErr.RequestID != "req_1" {
		t.Fatalf("unexpected request id: %s", pkErr.RequestID)
	}
	if polled {
		t.Fatal("should not poll status when a passkey is required")
	}
}

func TestLogin_Consume(t *testing.T) {
	var seenPath string
	client, closeFn := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		seenPath = r.URL.Path
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"consumed": true, "requestId": "req_1", "externalUsername": "a@b.com", "type": "LOGIN",
			"assurance": map[string]interface{}{"phishingResistant": false, "method": "push"},
		})
	})
	defer closeFn()

	resp, err := client.Login.Consume("req_1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if seenPath != "/login/req_1/consume" {
		t.Fatalf("unexpected path: %s", seenPath)
	}
	if !resp.Consumed || resp.Assurance == nil || resp.Assurance.Method != "push" {
		t.Fatalf("unexpected response: %+v", resp)
	}
}

func TestLogin_StatusParsesFullShape(t *testing.T) {
	client, closeFn := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"status": "CONFIRMED", "externalUsername": "a@b.com", "type": "SEND_MONEY", "referenceId": "tx-1",
			"details":  []interface{}{map[string]interface{}{"label": "Amount", "value": "250 EUR"}},
			"consumed": false, "confirmedVia": "DEVICE",
			"assurance": map[string]interface{}{"phishingResistant": false, "method": "push"},
		})
	})
	defer closeFn()

	resp, err := client.Login.Status("req_1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.ExternalUsername != "a@b.com" || resp.Type != "SEND_MONEY" || resp.ReferenceID != "tx-1" {
		t.Fatalf("unexpected response: %+v", resp)
	}
	if len(resp.Details) != 1 || resp.Details[0].Label != "Amount" || resp.Details[0].Value != "250 EUR" {
		t.Fatalf("unexpected details: %+v", resp.Details)
	}
	if resp.ConfirmedVia != "DEVICE" || resp.Assurance == nil || resp.Assurance.Method != "push" {
		t.Fatalf("unexpected response: %+v", resp)
	}
}
