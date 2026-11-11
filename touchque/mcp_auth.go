package touchque

// For an MCP server whose authorization server is Touchque SSO (Organization
// → MCP servers in the dashboard; issuer https://sso.touchque.com/mcp):
//
//   - ProtectedResourceMetadata is its RFC 9728 document, served at
//     MetadataPaths, so MCP clients find Touchque and ask for a token for
//     exactly this server;
//   - Verify checks a request's token: signed by Touchque (its JWKS), this
//     issuer, audience = this server's URL (RFC 8707), not expired, and for a
//     DPoP-bound token a fresh proof for this request; *McpAuthError carries
//     the status (401, 403) and the WWW-Authenticate header to send;
//   - RequireTool refuses with 403 insufficient_scope naming the scope a tool
//     needs, so the client asks the member for more.
//
//	auth, _ := touchque.NewMcpAuth(touchque.McpAuthConfig{
//		Issuer: "https://sso.touchque.com/mcp", Resource: "https://mcp.acme.com/mcp",
//		Tools:  map[string]string{"search_tickets": "tickets:read", "delete_ticket": "tickets:delete"},
//	})
//	http.Handle("/", auth.Middleware(mcpHandler)) // touchque.McpClaimsFrom(r.Context()) in a tool

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// McpAuthConfig configures NewMcpAuth.
type McpAuthConfig struct {
	// Issuer is Touchque SSO's MCP issuer, e.g. https://sso.touchque.com/mcp.
	Issuer string
	// Resource is this MCP server's URL, exactly as registered in Touchque.
	Resource string
	// Tools maps a tool name to the scope it needs (also listed as scopes_supported).
	Tools map[string]string
	// ResourceName is a human-readable name for the metadata.
	ResourceName string
	// ClockSkew allowed (default 60 s).
	ClockSkew time.Duration
	// HTTPClient reads the issuer's metadata and JWKS (default: 5 s timeout).
	HTTPClient *http.Client
}

// McpClaims is a verified token: the member (Sub, Email) an AI tool
// (ClientID, its client ID metadata document URL) acts for.
type McpClaims struct {
	Sub       string
	Email     string
	ClientID  string
	Scopes    []string
	OrgID     string
	ExpiresAt time.Time
	DPoPBound bool
	Claims    map[string]interface{}
}

// McpAuthError is a refused request: answer with Status and the
// WWW-Authenticate header. Code is missing_token, invalid_token,
// invalid_dpop_proof or insufficient_scope.
type McpAuthError struct {
	Status          int
	Code            string
	Message         string
	WWWAuthenticate string
}

func (e *McpAuthError) Error() string { return fmt.Sprintf("touchque: %s (%s)", e.Message, e.Code) }

// McpAuth verifies tokens Touchque SSO issued for one MCP server.
type McpAuth struct {
	issuer, resource, name string
	tools                  map[string]string
	skew                   time.Duration
	client                 *http.Client

	mu      sync.Mutex
	keys    map[string]crypto.PublicKey
	keysAt  time.Time
	triedAt time.Time
	proofs  map[string]time.Time
}

// NewMcpAuth needs Issuer and Resource.
func NewMcpAuth(cfg McpAuthConfig) (*McpAuth, error) {
	if cfg.Issuer == "" || cfg.Resource == "" {
		return nil, &ConfigError{Message: "McpAuth needs Issuer (Touchque SSO's MCP issuer) and Resource (this server's URL)"}
	}
	if _, err := url.Parse(cfg.Resource); err != nil {
		return nil, &ConfigError{Message: "Resource must be a URL"}
	}
	m := &McpAuth{issuer: strings.TrimRight(cfg.Issuer, "/"), resource: cfg.Resource, name: cfg.ResourceName, tools: cfg.Tools, skew: cfg.ClockSkew, client: cfg.HTTPClient, proofs: map[string]time.Time{}}
	if m.skew == 0 {
		m.skew = 60 * time.Second
	}
	if m.client == nil {
		m.client = &http.Client{Timeout: 5 * time.Second}
	}
	return m, nil
}

// MetadataPaths are where to serve ProtectedResourceMetadata.
func (m *McpAuth) MetadataPaths() []string {
	u, _ := url.Parse(m.resource)
	path := strings.TrimRight(u.Path, "/")
	if path == "" {
		return []string{"/.well-known/oauth-protected-resource"}
	}
	return []string{"/.well-known/oauth-protected-resource", "/.well-known/oauth-protected-resource" + path}
}

// MetadataURL is the resource_metadata URL in WWW-Authenticate.
func (m *McpAuth) MetadataURL() string {
	u, _ := url.Parse(m.resource)
	paths := m.MetadataPaths()
	return u.Scheme + "://" + u.Host + paths[len(paths)-1]
}

// ProtectedResourceMetadata is this server's RFC 9728 document.
func (m *McpAuth) ProtectedResourceMetadata() map[string]interface{} {
	scopes := []string{}
	seen := map[string]bool{}
	for _, s := range m.tools {
		if !seen[s] {
			seen[s] = true
			scopes = append(scopes, s)
		}
	}
	doc := map[string]interface{}{
		"resource": m.resource, "authorization_servers": []string{m.issuer}, "bearer_methods_supported": []string{"header"},
		"scopes_supported": scopes, "dpop_signing_alg_values_supported": []string{"ES256", "EdDSA"},
	}
	if m.name != "" {
		doc["resource_name"] = m.name
	}
	return doc
}

func (m *McpAuth) fail(status int, code, message, scope string) *McpAuthError {
	parts := []string{fmt.Sprintf("resource_metadata=%q", m.MetadataURL())}
	if code != "missing_token" {
		parts = append(parts, fmt.Sprintf("error=%q", code), fmt.Sprintf("error_description=\"%s\"", strings.ReplaceAll(message, `"`, "'")))
		if scope != "" {
			parts = append(parts, fmt.Sprintf("scope=%q", scope))
		}
	}
	return &McpAuthError{Status: status, Code: code, Message: message, WWWAuthenticate: "Bearer " + strings.Join(parts, ", ")}
}

func mcpJSONPart(part string) (map[string]interface{}, error) {
	raw, err := base64.RawURLEncoding.DecodeString(part)
	if err != nil {
		return nil, err
	}
	out := map[string]interface{}{}
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, err
	}
	return out, nil
}

func mcpPublicKey(jwk map[string]interface{}) (crypto.PublicKey, error) {
	field := func(k string) ([]byte, error) {
		s, _ := jwk[k].(string)
		return base64.RawURLEncoding.DecodeString(s)
	}
	switch {
	case jwk["kty"] == "RSA":
		n, err1 := field("n")
		e, err2 := field("e")
		if err1 != nil || err2 != nil || len(e) > 4 {
			return nil, errors.New("bad RSA key")
		}
		return &rsa.PublicKey{N: new(big.Int).SetBytes(n), E: int(new(big.Int).SetBytes(e).Int64())}, nil
	case jwk["kty"] == "EC" && jwk["crv"] == "P-256":
		x, err1 := field("x")
		y, err2 := field("y")
		if err1 != nil || err2 != nil {
			return nil, errors.New("bad EC key")
		}
		pub := &ecdsa.PublicKey{Curve: elliptic.P256(), X: new(big.Int).SetBytes(x), Y: new(big.Int).SetBytes(y)}
		if !pub.Curve.IsOnCurve(pub.X, pub.Y) {
			return nil, errors.New("not on P-256")
		}
		return pub, nil
	case jwk["kty"] == "OKP" && jwk["crv"] == "Ed25519":
		x, err := field("x")
		if err != nil || len(x) != ed25519.PublicKeySize {
			return nil, errors.New("bad Ed25519 key")
		}
		return ed25519.PublicKey(x), nil
	}
	return nil, errors.New("unsupported key")
}

func mcpVerifySignature(input string, sig []byte, alg string, key crypto.PublicKey) bool {
	sum := sha256.Sum256([]byte(input))
	switch k := key.(type) {
	case *rsa.PublicKey:
		return alg == "RS256" && rsa.VerifyPKCS1v15(k, crypto.SHA256, sum[:], sig) == nil
	case *ecdsa.PublicKey:
		return alg == "ES256" && len(sig) == 64 && ecdsa.Verify(k, sum[:], new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:]))
	case ed25519.PublicKey:
		return alg == "EdDSA" && ed25519.Verify(k, []byte(input), sig)
	}
	return false
}

func (m *McpAuth) getJSON(ctx context.Context, target string) (map[string]interface{}, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", target, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	resp, err := m.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("%s answered %d", target, resp.StatusCode)
	}
	out := map[string]interface{}{}
	return out, json.NewDecoder(resp.Body).Decode(&out)
}

func (m *McpAuth) loadKeys(ctx context.Context) error {
	u, err := url.Parse(m.issuer)
	if err != nil {
		return err
	}
	meta, err := m.getJSON(ctx, u.Scheme+"://"+u.Host+"/.well-known/oauth-authorization-server"+strings.TrimRight(u.Path, "/"))
	if err != nil {
		return err
	}
	iss, _ := meta["issuer"].(string)
	jwksURI, _ := meta["jwks_uri"].(string)
	if strings.TrimRight(iss, "/") != m.issuer || jwksURI == "" {
		return errors.New("the authorization server metadata does not match the issuer")
	}
	jwks, err := m.getJSON(ctx, jwksURI)
	if err != nil {
		return err
	}
	keys := map[string]crypto.PublicKey{}
	list, _ := jwks["keys"].([]interface{})
	for _, item := range list {
		jwk, _ := item.(map[string]interface{})
		kid, _ := jwk["kid"].(string)
		if key, err := mcpPublicKey(jwk); err == nil && kid != "" {
			keys[kid] = key
		}
	}
	m.keys, m.keysAt = keys, time.Now()
	return nil
}

func (m *McpAuth) keyFor(ctx context.Context, kid string) (crypto.PublicKey, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.keys == nil || time.Since(m.keysAt) > 10*time.Minute {
		if err := m.loadKeys(ctx); err != nil {
			return nil, err
		}
	}
	if _, ok := m.keys[kid]; !ok && time.Since(m.triedAt) > time.Minute {
		m.triedAt = time.Now()
		if err := m.loadKeys(ctx); err != nil {
			return nil, err
		}
	}
	return m.keys[kid], nil
}

func (m *McpAuth) claims(ctx context.Context, token string) (map[string]interface{}, error) {
	parts := strings.Split(token, ".")
	head, err1 := mcpJSONPart(parts[0])
	claims, err2 := mcpJSONPart(parts[1])
	sig, err3 := base64.RawURLEncoding.DecodeString(parts[2])
	if err1 != nil || err2 != nil || err3 != nil {
		return nil, m.fail(401, "invalid_token", "The token is malformed", "")
	}
	alg, _ := head["alg"].(string)
	if head["typ"] != "at+jwt" || (alg != "RS256" && alg != "ES256") {
		return nil, m.fail(401, "invalid_token", "Not a Touchque access token", "")
	}
	kid, _ := head["kid"].(string)
	key, err := m.keyFor(ctx, kid)
	if err != nil {
		return nil, m.fail(401, "invalid_token", "The authorization server's keys could not be read", "")
	}
	if key == nil || !mcpVerifySignature(parts[0]+"."+parts[1], sig, alg, key) {
		return nil, m.fail(401, "invalid_token", "The token signature does not verify", "")
	}
	if iss, _ := claims["iss"].(string); strings.TrimRight(iss, "/") != m.issuer {
		return nil, m.fail(401, "invalid_token", "The token is from another issuer", "")
	}
	audOK := false
	switch aud := claims["aud"].(type) {
	case string:
		audOK = aud == m.resource
	case []interface{}:
		for _, a := range aud {
			audOK = audOK || a == m.resource
		}
	}
	if !audOK {
		return nil, m.fail(401, "invalid_token", "The token is for another server", "")
	}
	exp, ok := claims["exp"].(float64)
	if !ok || time.Unix(int64(exp), 0).Add(m.skew).Before(time.Now()) {
		return nil, m.fail(401, "invalid_token", "The token expired", "")
	}
	return claims, nil
}

// Verify checks a request's token. The DPoP proof's htu is compared with
// Resource's origin plus the request path, so it holds behind a proxy that
// terminates TLS.
func (m *McpAuth) Verify(r *http.Request) (*McpClaims, error) {
	scheme, token, _ := strings.Cut(strings.TrimSpace(r.Header.Get("Authorization")), " ")
	scheme = strings.ToLower(scheme)
	token = strings.TrimSpace(token)
	if (scheme != "bearer" && scheme != "dpop") || strings.Count(token, ".") != 2 {
		return nil, m.fail(401, "missing_token", "A Touchque access token is required", "")
	}
	claims, err := m.claims(r.Context(), token)
	if err != nil {
		return nil, err
	}
	cnf, _ := claims["cnf"].(map[string]interface{})
	jkt, _ := cnf["jkt"].(string)
	if jkt != "" {
		if scheme != "dpop" {
			return nil, m.fail(401, "invalid_token", "This token is bound to a DPoP key: send it as DPoP with a proof", "")
		}
		u, _ := url.Parse(m.resource)
		if err := m.checkProof(r.Header.Get("DPoP"), r.Method, u.Scheme+"://"+u.Host+r.URL.Path, token, jkt); err != nil {
			return nil, m.fail(401, "invalid_dpop_proof", "DPoP proof: "+err.Error(), "")
		}
	}
	out := &McpClaims{Claims: claims, DPoPBound: jkt != "", ExpiresAt: time.Unix(int64(claims["exp"].(float64)), 0)}
	out.Sub, _ = claims["sub"].(string)
	out.Email, _ = claims["email"].(string)
	out.ClientID, _ = claims["client_id"].(string)
	out.OrgID, _ = claims["org_id"].(string)
	scope, _ := claims["scope"].(string)
	out.Scopes = strings.Fields(scope)
	return out, nil
}

func (m *McpAuth) checkProof(proof, method, htu, token, jkt string) error {
	parts := strings.Split(proof, ".")
	if len(parts) != 3 {
		return errors.New("missing")
	}
	head, err1 := mcpJSONPart(parts[0])
	claims, err2 := mcpJSONPart(parts[1])
	sig, err3 := base64.RawURLEncoding.DecodeString(parts[2])
	if err1 != nil || err2 != nil || err3 != nil {
		return errors.New("malformed")
	}
	jwk, _ := head["jwk"].(map[string]interface{})
	if head["typ"] != "dpop+jwt" || jwk == nil || jwk["d"] != nil || (jwk["kty"] != "EC" && jwk["kty"] != "OKP") || JWKThumbprint(jwk) != jkt {
		return errors.New("not the bound key")
	}
	key, err := mcpPublicKey(jwk)
	alg, _ := head["alg"].(string)
	if err != nil || !mcpVerifySignature(parts[0]+"."+parts[1], sig, alg, key) {
		return errors.New("signature")
	}
	if claims["htm"] != strings.ToUpper(method) || claims["htu"] != htu {
		return errors.New("htm/htu")
	}
	iat, _ := claims["iat"].(float64)
	if d := time.Since(time.Unix(int64(iat), 0)); d > m.skew || d < -m.skew {
		return errors.New("iat")
	}
	sum := sha256.Sum256([]byte(token))
	if claims["ath"] != b64url(sum[:]) {
		return errors.New("ath")
	}
	jti, _ := claims["jti"].(string)
	m.mu.Lock()
	defer m.mu.Unlock()
	now := time.Now()
	for k, until := range m.proofs {
		if until.Before(now) {
			delete(m.proofs, k)
		}
	}
	if _, used := m.proofs[jti]; jti == "" || used {
		return errors.New("jti used")
	}
	m.proofs[jti] = now.Add(2 * m.skew)
	return nil
}

// RequireScope refuses with 403 insufficient_scope unless the token has scope.
func (m *McpAuth) RequireScope(c *McpClaims, scope string) error {
	for _, s := range c.Scopes {
		if s == scope {
			return nil
		}
	}
	return m.fail(403, "insufficient_scope", "This needs the "+scope+" scope", scope)
}

// RequireTool refuses with 403 insufficient_scope unless the token has the tool's scope.
func (m *McpAuth) RequireTool(c *McpClaims, tool string) error {
	scope := m.tools[tool]
	if scope == "" {
		return m.fail(403, "insufficient_scope", "No scope is set for the tool "+tool, "")
	}
	return m.RequireScope(c, scope)
}

type mcpClaimsKey struct{}

// McpClaimsFrom is the verified token Middleware put in the request context.
func McpClaimsFrom(ctx context.Context) *McpClaims {
	c, _ := ctx.Value(mcpClaimsKey{}).(*McpClaims)
	return c
}

// WriteMcpAuthError answers a refusal (an *McpAuthError) with its status and WWW-Authenticate.
func WriteMcpAuthError(w http.ResponseWriter, err error) {
	var e *McpAuthError
	if !errors.As(err, &e) {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("WWW-Authenticate", e.WWWAuthenticate)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(e.Status)
	code := e.Code
	if code == "missing_token" {
		code = "invalid_token"
	}
	_ = json.NewEncoder(w).Encode(map[string]string{"error": code, "error_description": e.Message})
}

// Middleware serves the protected resource metadata at MetadataPaths and
// verifies every other request; the claims are in McpClaimsFrom(r.Context()).
func (m *McpAuth) Middleware(next http.Handler) http.Handler {
	paths := map[string]bool{}
	for _, p := range m.MetadataPaths() {
		paths[p] = true
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet && paths[r.URL.Path] {
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Access-Control-Allow-Origin", "*")
			_ = json.NewEncoder(w).Encode(m.ProtectedResourceMetadata())
			return
		}
		claims, err := m.Verify(r)
		if err != nil {
			WriteMcpAuthError(w, err)
			return
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), mcpClaimsKey{}, claims)))
	})
}
