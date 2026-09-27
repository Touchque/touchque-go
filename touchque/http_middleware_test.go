package touchque

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func requireHandler(c *Client, action string) http.Handler {
	protected := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		approval, _ := ApprovalFromContext(r.Context())
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"done": true, "touchque": approval})
	})
	return Require(c, action, protected, RequireOptions{
		User: func(r *http.Request) string { return r.Header.Get("X-User") },
		Details: func(r *http.Request) []LoginDetail {
			return []LoginDetail{{Label: "Amount", Value: "5 EUR"}}
		},
	})
}

func TestRequire_FullFlow(t *testing.T) {
	api := startFakeAPI(t)
	api.link("jane@acme.com")
	api.opts(map[string]interface{}{"numberMatch": true})
	c := api.client(t)
	handler := requireHandler(c, "SEND_MONEY")

	req1 := httptest.NewRequest(http.MethodPost, "/transfer", nil)
	req1.Header.Set("X-User", "jane@acme.com")
	rec1 := httptest.NewRecorder()
	handler.ServeHTTP(rec1, req1)
	if rec1.Code != 202 {
		t.Fatalf("expected 202, got %d: %s", rec1.Code, rec1.Body.String())
	}
	var first struct {
		Touchque Step   `json:"touchque"`
		Token    string `json:"token"`
	}
	if err := json.Unmarshal(rec1.Body.Bytes(), &first); err != nil {
		t.Fatalf("bad json: %v", err)
	}
	if first.Touchque.Number != "47" {
		t.Fatalf("expected number matching digits, got %+v", first.Touchque)
	}

	api.approve("")
	req2 := httptest.NewRequest(http.MethodPost, "/transfer", nil)
	req2.Header.Set("X-User", "jane@acme.com")
	req2.Header.Set(GuardTokenHeader, first.Token)
	rec2 := httptest.NewRecorder()
	handler.ServeHTTP(rec2, req2)
	if rec2.Code != 200 {
		t.Fatalf("expected 200, got %d: %s", rec2.Code, rec2.Body.String())
	}
	var done struct {
		Done bool `json:"done"`
	}
	_ = json.Unmarshal(rec2.Body.Bytes(), &done)
	if !done.Done {
		t.Fatal("expected the protected handler to have run")
	}

	// Replaying the same token must not run the handler again.
	req3 := httptest.NewRequest(http.MethodPost, "/transfer", nil)
	req3.Header.Set("X-User", "jane@acme.com")
	req3.Header.Set(GuardTokenHeader, first.Token)
	rec3 := httptest.NewRecorder()
	handler.ServeHTTP(rec3, req3)
	if rec3.Code == 200 {
		t.Fatal("expected the replayed token to be refused")
	}
}

func TestRequire_NoUserIs401(t *testing.T) {
	api := startFakeAPI(t)
	c := api.client(t)
	handler := requireHandler(c, "SEND_MONEY")

	req := httptest.NewRequest(http.MethodPost, "/transfer", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != 401 {
		t.Fatalf("expected 401, got %d", rec.Code)
	}
}
