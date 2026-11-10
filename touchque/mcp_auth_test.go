package touchque

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"
)

// McpAuth (an MCP server whose authorization server is TouchQue SSO) against
// the shared fake API's MCP issuer: metadata, audience, issuer, expiry, scopes
// per tool, DPoP-bound tokens and their proofs, and the middleware.

const mcpResource = "https://mcp.acme.example/mcp"

func mcpToken(t *testing.T, base string, extra map[string]interface{}) string {
	t.Helper()
	body := map[string]interface{}{"aud": mcpResource, "scope": "tickets:read"}
	for k, v := range extra {
		body[k] = v
	}
	return fakePost(t, base, "/__test/mcp-token", body)["token"].(string)
}

func newTestMcpAuth(t *testing.T, base string) *McpAuth {
	t.Helper()
	auth, err := NewMcpAuth(McpAuthConfig{Issuer: base + "/mcp-as", Resource: mcpResource, Tools: map[string]string{"search_tickets": "tickets:read", "delete_ticket": "tickets:delete"}})
	if err != nil {
		t.Fatal(err)
	}
	return auth
}

func mcpRequest(auth, dpop string) *http.Request {
	r := httptest.NewRequest("POST", "http://127.0.0.1:8080/mcp", nil)
	if auth != "" {
		r.Header.Set("Authorization", auth)
	}
	if dpop != "" {
		r.Header.Set("DPoP", dpop)
	}
	return r
}

func mcpCode(err error) string {
	var e *McpAuthError
	if errors.As(err, &e) {
		return e.Code
	}
	return ""
}

func TestMcpAuthTokensAndScopes(t *testing.T) {
	api := startFakeAPI(t)
	auth := newTestMcpAuth(t, api.baseURL)
	if got := strings.Join(auth.MetadataPaths(), " "); got != "/.well-known/oauth-protected-resource /.well-known/oauth-protected-resource/mcp" {
		t.Fatal(got)
	}
	claims, err := auth.Verify(mcpRequest("Bearer "+mcpToken(t, api.baseURL, nil), ""))
	if err != nil || claims.Sub != "user-1" || claims.ClientID != "https://tool.example/client.json" || claims.DPoPBound {
		t.Fatal(claims, err)
	}
	if err := auth.RequireTool(claims, "search_tickets"); err != nil {
		t.Fatal(err)
	}
	var e *McpAuthError
	if err := auth.RequireTool(claims, "delete_ticket"); !errors.As(err, &e) || e.Status != 403 || !strings.Contains(e.WWWAuthenticate, `scope="tickets:delete"`) {
		t.Fatal(err)
	}
	if _, err := auth.Verify(mcpRequest("", "")); !errors.As(err, &e) || e.WWWAuthenticate != `Bearer resource_metadata="https://mcp.acme.example/.well-known/oauth-protected-resource/mcp"` {
		t.Fatal(err)
	}
	for _, bad := range []map[string]interface{}{{"aud": "https://other.example/mcp"}, {"iss": "https://evil.example/mcp"}, {"expiresIn": -120}, {"typ": "JWT"}} {
		if _, err := auth.Verify(mcpRequest("Bearer "+mcpToken(t, api.baseURL, bad), "")); mcpCode(err) != "invalid_token" {
			t.Fatal(bad, err)
		}
	}

	h := auth.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(McpClaimsFrom(r.Context()).Sub))
	}))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "/.well-known/oauth-protected-resource/mcp", nil))
	meta := map[string]interface{}{}
	_ = json.Unmarshal(rec.Body.Bytes(), &meta)
	if meta["resource"] != mcpResource {
		t.Fatal(rec.Body.String())
	}
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, mcpRequest("", ""))
	if rec.Code != 401 || rec.Header().Get("WWW-Authenticate") == "" {
		t.Fatal(rec.Code)
	}
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, mcpRequest("Bearer "+mcpToken(t, api.baseURL, nil), ""))
	if rec.Code != 200 || rec.Body.String() != "user-1" {
		t.Fatal(rec.Code, rec.Body.String())
	}
}

func TestMcpAuthDPoPBound(t *testing.T) {
	api := startFakeAPI(t)
	auth := newTestMcpAuth(t, api.baseURL)
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	jwk := ecPublicJWK(&key.PublicKey)
	token := mcpToken(t, api.baseURL, map[string]interface{}{"jkt": JWKThumbprint(jwk)})
	n := 0
	proof := func(htu string) string {
		n++
		head, _ := json.Marshal(map[string]interface{}{"typ": "dpop+jwt", "alg": "ES256", "jwk": jwk})
		sum := sha256.Sum256([]byte(token))
		body, _ := json.Marshal(map[string]interface{}{"htm": "POST", "htu": htu, "iat": time.Now().Unix(), "jti": "p-" + strconv.Itoa(n), "ath": b64url(sum[:])})
		input := b64url(head) + "." + b64url(body)
		digest := sha256.Sum256([]byte(input))
		r, s, _ := ecdsa.Sign(rand.Reader, key, digest[:])
		sig := make([]byte, 64)
		r.FillBytes(sig[:32])
		s.FillBytes(sig[32:])
		return input + "." + b64url(sig)
	}
	if _, err := auth.Verify(mcpRequest("Bearer "+token, "")); mcpCode(err) != "invalid_token" {
		t.Fatal(err)
	}
	good := proof(mcpResource)
	if c, err := auth.Verify(mcpRequest("DPoP "+token, good)); err != nil || !c.DPoPBound {
		t.Fatal(err)
	}
	if _, err := auth.Verify(mcpRequest("DPoP "+token, good)); mcpCode(err) != "invalid_dpop_proof" {
		t.Fatal("replayed proof accepted", err)
	}
	if _, err := auth.Verify(mcpRequest("DPoP "+token, proof("https://other.example/mcp"))); mcpCode(err) != "invalid_dpop_proof" {
		t.Fatal("proof for another URL accepted", err)
	}
}
