package touchque

import (
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
)

// unusedLocalAddr binds an ephemeral port and immediately releases it, so
// the returned address is guaranteed to refuse connections instantly
// (rather than risking a slow/ambiguous timeout against a fixed low port
// like :1, which can behave inconsistently across sandboxed environments).
func unusedLocalAddr(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("could not reserve an ephemeral port: %v", err)
	}
	addr := l.Addr().String()
	_ = l.Close()
	return addr
}

func testConfig(baseURL string) *Config {
	return &Config{APIKey: "tq_auth_test123", APISecret: "shh", BaseURL: baseURL, TimeoutMs: 5000}
}

func TestPost_AttachesSignedHeaders(t *testing.T) {
	var gotHeaders http.Header
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotHeaders = r.Header
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"ok": true})
	}))
	defer server.Close()

	client := newHTTPClient(testConfig(server.URL))
	result, err := client.post("/auth/generate-secret", map[string]interface{}{"externalUsername": "a@b.com"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result["ok"] != true {
		t.Fatalf("expected ok:true, got %v", result)
	}
	if gotHeaders.Get("x-api-key") != "tq_auth_test123" {
		t.Fatalf("expected x-api-key header, got %q", gotHeaders.Get("x-api-key"))
	}
	if len(gotHeaders.Get("x-signature")) != 64 {
		t.Fatalf("expected 64-char hex signature, got %q", gotHeaders.Get("x-signature"))
	}
	if gotHeaders.Get("x-nonce") == "" || gotHeaders.Get("x-timestamp") == "" {
		t.Fatal("expected x-nonce and x-timestamp headers to be set")
	}
}

func TestPost_TwoCallsProduceDifferentNonces(t *testing.T) {
	var nonces []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nonces = append(nonces, r.Header.Get("x-nonce"))
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"ok": true})
	}))
	defer server.Close()

	client := newHTTPClient(testConfig(server.URL))
	_, _ = client.post("/login/request", map[string]interface{}{"a": 1})
	_, _ = client.post("/login/request", map[string]interface{}{"a": 1})

	if len(nonces) != 2 || nonces[0] == nonces[1] {
		t.Fatalf("expected two distinct nonces, got %v", nonces)
	}
}

func TestGet_SignsEmptyBodyRequest(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if len(r.Header.Get("x-signature")) != 64 {
			t.Errorf("expected signed GET request")
		}
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"status": "PENDING"})
	}))
	defer server.Close()

	client := newHTTPClient(testConfig(server.URL))
	result, err := client.get("/login/status/req_1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result["status"] != "PENDING" {
		t.Fatalf("expected status PENDING, got %v", result)
	}
}

func TestPost_WrapsNon2xxIntoAPIError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"error": "unauthorized", "message": "Invalid API key"})
	}))
	defer server.Close()

	client := newHTTPClient(testConfig(server.URL))
	_, err := client.post("/auth/generate-secret", map[string]interface{}{})
	if err == nil {
		t.Fatal("expected an error")
	}
	apiErr, ok := err.(*APIError)
	if !ok {
		t.Fatalf("expected *APIError, got %T", err)
	}
	if apiErr.StatusCode != 401 {
		t.Fatalf("expected status 401, got %d", apiErr.StatusCode)
	}
}

func TestPost_WrapsNetworkErrors(t *testing.T) {
	// Point at a freshly-released ephemeral port — guaranteed nothing is
	// listening there, so the connection is refused immediately.
	client := newHTTPClient(testConfig("http://" + unusedLocalAddr(t)))
	_, err := client.post("/auth/generate-secret", map[string]interface{}{})
	if err == nil {
		t.Fatal("expected a network error")
	}
	if _, ok := err.(*NetworkError); !ok {
		t.Fatalf("expected *NetworkError, got %T", err)
	}
}

func TestGet_SignsTheQueryString(t *testing.T) {
	var gotPath string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.RequestURI()
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"credentials": []interface{}{}})
	}))
	defer server.Close()

	client := newHTTPClient(testConfig(server.URL))
	_, err := client.getWithQuery("/webauthn/credentials", map[string]string{"externalUsername": "a@b.com"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if gotPath != "/webauthn/credentials?externalUsername=a%40b.com" {
		t.Fatalf("unexpected request URI: %s", gotPath)
	}
}

func TestPost_4xxCarriesCodeReasonAndRetryAfter(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Retry-After", "60")
		w.WriteHeader(http.StatusTooManyRequests)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"error": "too_many_login_requests", "code": "rate_limited"})
	}))
	defer server.Close()

	client := newHTTPClient(testConfig(server.URL))
	_, err := client.post("/login/request", map[string]interface{}{})
	apiErr, ok := err.(*APIError)
	if !ok {
		t.Fatalf("expected *APIError, got %T", err)
	}
	if apiErr.Code != "rate_limited" || apiErr.RetryAfter != 60 {
		t.Fatalf("unexpected error: %+v", apiErr)
	}
}
