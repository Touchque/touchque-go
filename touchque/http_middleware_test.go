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

func TestRequire_PanicsWithoutUserResolver(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("Require without RequireOptions.User must panic")
		}
	}()
	Require(&Client{}, "SEND_MONEY", http.NotFoundHandler(), RequireOptions{})
}

func TestRequire_IgnoresClientSuppliedUserHeader(t *testing.T) {
	api := startFakeAPI(t)
	api.link("victim@acme.com")
	c := api.client(t)
	handler := Require(c, "SEND_MONEY", http.NotFoundHandler(), RequireOptions{
		User: func(r *http.Request) string { return "" }, // nobody signed in
	})
	req := httptest.NewRequest(http.MethodPost, "/transfer", nil)
	req.Header.Set("X-Touchque-User", "victim@acme.com")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != 401 {
		t.Fatalf("expected 401 for an anonymous request, got %d: %s", rec.Code, rec.Body.String())
	}
}

// R1-01: the API needs an address, not "ip:port" — with the port it fell
// back to scoring the partner's server.
func TestRequire_SendsHostOnlyClientIP(t *testing.T) {
	api := startFakeAPI(t)
	api.link("jane@acme.com")
	c := api.client(t)
	handler := requireHandler(c, "SEND_MONEY")

	for _, remote := range []string{"192.0.2.1:1234", "[2001:db8::1]:443"} {
		req := httptest.NewRequest(http.MethodPost, "/transfer", nil)
		req.RemoteAddr = remote
		req.Header.Set("X-User", "jane@acme.com")
		handler.ServeHTTP(httptest.NewRecorder(), req)
	}
	var got []interface{}
	for _, call := range api.calls() {
		if call["path"] == "/login/request" {
			body, _ := call["body"].(map[string]interface{})
			got = append(got, body["clientIp"])
		}
	}
	if len(got) != 2 || got[0] != "192.0.2.1" || got[1] != "2001:db8::1" {
		t.Fatalf("clientIp sent: %v", got)
	}
}

func TestHostOnly(t *testing.T) {
	for in, want := range map[string]string{"192.0.2.1:80": "192.0.2.1", "[::1]:80": "::1", "192.0.2.1": "192.0.2.1", "2001:db8::1": "2001:db8::1"} {
		if got := hostOnly(in); got != want {
			t.Errorf("hostOnly(%q) = %q, want %q", in, got, want)
		}
	}
}
