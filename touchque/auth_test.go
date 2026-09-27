package touchque

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func newTestClient(t *testing.T, handler http.HandlerFunc) (*Client, func()) {
	t.Helper()
	server := httptest.NewServer(handler)
	client := NewClient(&Config{APIKey: "tq_auth_test123", APISecret: "shh", BaseURL: server.URL, TimeoutMs: 5000})
	return client, server.Close
}

func TestAuth_GenerateSecret(t *testing.T) {
	client, closeFn := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/auth/generate-secret" {
			t.Errorf("expected /auth/generate-secret, got %s", r.URL.Path)
		}
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"secret": "s", "expiresAt": "t", "ttlMs": float64(60000)})
	})
	defer closeFn()

	resp, err := client.Auth.GenerateSecret("a@b.com")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.Secret != "s" || resp.TTLMs != 60000 {
		t.Fatalf("unexpected response: %+v", resp)
	}
}

func TestAuth_ResetSecret(t *testing.T) {
	client, closeFn := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/auth/secret/reset" {
			t.Errorf("expected /auth/secret/reset, got %s", r.URL.Path)
		}
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"secret": "new"})
	})
	defer closeFn()

	resp, err := client.Auth.ResetSecret("a@b.com")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.Secret != "new" {
		t.Fatalf("unexpected response: %+v", resp)
	}
}

func TestAuth_ValidateSecret(t *testing.T) {
	client, closeFn := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/auth/secret/validate" {
			t.Errorf("expected /auth/secret/validate, got %s", r.URL.Path)
		}
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"valid": true})
	})
	defer closeFn()

	resp, err := client.Auth.ValidateSecret("123456")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !resp.Valid {
		t.Fatalf("expected valid:true, got %+v", resp)
	}
}

func TestAuth_GetUser(t *testing.T) {
	client, closeFn := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/users/a+x@b.com" {
			t.Errorf("expected /users/a+x@b.com, got %s", r.URL.Path)
		}
		if r.Method != "GET" {
			t.Errorf("expected GET, got %s", r.Method)
		}
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"externalUsername": "a@b.com", "used": false, "frozen": false,
		})
	})
	defer closeFn()

	resp, err := client.Auth.GetUser("a+x@b.com")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.Used {
		t.Fatalf("expected used=false, got %+v", resp)
	}
}
