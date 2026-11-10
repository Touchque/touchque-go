package touchque

// Cross App Access: Identity Assertion JWT Authorization Grants (ID-JAG,
// draft-ietf-oauth-identity-assertion-authz-grant, an open standard). An
// organization's identity provider (TouchQue SSO) decides which of its apps
// may reach which other service for its members; the app trades a member's ID
// token for an ID-JAG there, then the ID-JAG for an access token at the other
// service's authorization server, with no consent screen per member.
//
// Your app, signed in with TouchQue SSO (an OpenID Connect app with a secret):
//
//	jag, err := touchque.RequestIDJAG(ctx, touchque.RequestIDJAGParams{Issuer: "https://sso.touchque.com",
//		ClientID: clientID, ClientSecret: secret, IDToken: idToken, Audience: "https://auth.files.example"})
//	tokens, err := touchque.RedeemIDJAG(ctx, touchque.RedeemIDJAGParams{TokenEndpoint: "https://auth.files.example/token",
//		ClientID: "acme", ClientSecret: filesSecret, Assertion: jag.Assertion})
//
// Your own authorization server, taking ID-JAGs from an organization's identity provider:
//
//	v, _ := touchque.NewIDJAGVerifier(touchque.IDJAGVerifierConfig{Issuer: "https://sso.touchque.com", Audience: "https://auth.files.example"})
//	claims, err := v.Verify(ctx, r.PostFormValue("assertion"), authenticatedClientID)

import (
	"context"
	"crypto"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

const (
	IDJAGTokenType     = "urn:ietf:params:oauth:token-type:id-jag"
	IDTokenTokenType   = "urn:ietf:params:oauth:token-type:id_token"
	TokenExchangeGrant = "urn:ietf:params:oauth:grant-type:token-exchange"
	JWTBearerGrant     = "urn:ietf:params:oauth:grant-type:jwt-bearer"
	idJagTyp           = "oauth-id-jag+jwt"
)

// IDJAGError is a refused ID-JAG or exchange; Code is the OAuth error
// (invalid_grant for a bad ID-JAG).
type IDJAGError struct {
	Code    string
	Message string
	Status  int
}

func (e *IDJAGError) Error() string { return fmt.Sprintf("touchque: %s (%s)", e.Message, e.Code) }

// IDJAGVerifierConfig configures a verifier at your authorization server.
type IDJAGVerifierConfig struct {
	// Issuer is the identity provider, e.g. https://sso.touchque.com.
	Issuer string
	// Audience is your authorization server's issuer identifier (the ID-JAG's aud).
	Audience string
	// JWKSURI, when not found from the issuer's /.well-known/openid-configuration.
	JWKSURI string
	// ClockSkew allowed (default 60 s).
	ClockSkew time.Duration
	// FirstUse records an ID-JAG's jti and says whether it is new (each is used
	// once). Defaults to memory in this process; give a shared store (Redis SET
	// NX) when several processes take ID-JAGs.
	FirstUse   func(jti string, expiresAt int64) bool
	HTTPClient *http.Client
}

// IDJAGClaims is a checked ID-JAG.
type IDJAGClaims struct {
	Iss       string
	Sub       string // the member at the identity provider
	Aud       string
	ClientID  string // your client_id of the app that presented it
	JTI       string
	IssuedAt  int64
	ExpiresAt int64
	Scopes    []string
	Resource  string
	Tenant    string
	Email     string
	AuthTime  int64
	AMR       []string
	Claims    map[string]interface{}
}

// IDJAGVerifier checks the ID-JAG an authenticated client presents (jwt-bearer grant).
type IDJAGVerifier struct {
	cfg     IDJAGVerifierConfig
	mu      sync.Mutex
	jwksURI string
	keys    map[string]crypto.PublicKey
	keysAt  time.Time
	triedAt time.Time
	seen    map[string]int64
}

// NewIDJAGVerifier needs Issuer and Audience.
func NewIDJAGVerifier(cfg IDJAGVerifierConfig) (*IDJAGVerifier, error) {
	if cfg.Issuer == "" || cfg.Audience == "" {
		return nil, errors.New("touchque: IDJAGVerifier needs Issuer (the identity provider) and Audience (your authorization server's issuer)")
	}
	if cfg.ClockSkew == 0 {
		cfg.ClockSkew = 60 * time.Second
	}
	if cfg.HTTPClient == nil {
		cfg.HTTPClient = &http.Client{Timeout: 5 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	}
	return &IDJAGVerifier{cfg: cfg, jwksURI: cfg.JWKSURI, seen: map[string]int64{}}, nil
}

func xaaGetJSON(ctx context.Context, client *http.Client, target string) (map[string]interface{}, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", target, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("%s answered %d", target, resp.StatusCode)
	}
	out := map[string]interface{}{}
	return out, json.NewDecoder(resp.Body).Decode(&out)
}

func xaaDiscover(ctx context.Context, client *http.Client, issuer string) (map[string]interface{}, error) {
	meta, err := xaaGetJSON(ctx, client, strings.TrimRight(issuer, "/")+"/.well-known/openid-configuration")
	if err != nil {
		return nil, err
	}
	if meta["issuer"] != issuer {
		return nil, errors.New("the identity provider's metadata does not match its issuer")
	}
	return meta, nil
}

func (v *IDJAGVerifier) loadKeys(ctx context.Context) error {
	if v.jwksURI == "" {
		meta, err := xaaDiscover(ctx, v.cfg.HTTPClient, v.cfg.Issuer)
		if err != nil {
			return err
		}
		uri, _ := meta["jwks_uri"].(string)
		if uri == "" {
			return errors.New("the identity provider names no jwks_uri")
		}
		v.jwksURI = uri
	}
	jwks, err := xaaGetJSON(ctx, v.cfg.HTTPClient, v.jwksURI)
	if err != nil {
		return err
	}
	keys := map[string]crypto.PublicKey{}
	list, _ := jwks["keys"].([]interface{})
	for _, raw := range list {
		k, _ := raw.(map[string]interface{})
		kid, _ := k["kid"].(string)
		if pub, err := mcpPublicKey(k); err == nil && kid != "" {
			keys[kid] = pub
		}
	}
	v.keys = keys
	v.keysAt = time.Now()
	return nil
}

func (v *IDJAGVerifier) keyFor(ctx context.Context, kid string) (crypto.PublicKey, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.keysAt.IsZero() || time.Since(v.keysAt) > 10*time.Minute {
		if err := v.loadKeys(ctx); err != nil {
			return nil, err
		}
	}
	if _, ok := v.keys[kid]; !ok && time.Since(v.triedAt) > time.Minute {
		v.triedAt = time.Now()
		if err := v.loadKeys(ctx); err != nil {
			return nil, err
		}
	}
	return v.keys[kid], nil
}

func (v *IDJAGVerifier) rememberOnce(jti string, exp int64) bool {
	v.mu.Lock()
	defer v.mu.Unlock()
	now := time.Now().Unix()
	for k, until := range v.seen {
		if until < now {
			delete(v.seen, k)
		}
	}
	if _, ok := v.seen[jti]; ok {
		return false
	}
	v.seen[jti] = exp + int64(v.cfg.ClockSkew/time.Second)
	return true
}

// Verify checks the ID-JAG and uses it once: its claims, or *IDJAGError (Code invalid_grant).
func (v *IDJAGVerifier) Verify(ctx context.Context, assertion, clientID string) (*IDJAGClaims, error) {
	bad := func(m string) error { return &IDJAGError{Code: "invalid_grant", Message: m} }
	parts := strings.Split(assertion, ".")
	if len(parts) != 3 {
		return nil, bad("assertion is not a JWT")
	}
	head, err1 := mcpJSONPart(parts[0])
	c, err2 := mcpJSONPart(parts[1])
	if err1 != nil || err2 != nil {
		return nil, bad("assertion is not a JWT")
	}
	if head["typ"] != idJagTyp {
		return nil, bad("not an ID-JAG (typ oauth-id-jag+jwt)")
	}
	alg, _ := head["alg"].(string)
	kid, _ := head["kid"].(string)
	if (alg != "RS256" && alg != "ES256" && alg != "EdDSA") || kid == "" {
		return nil, bad("unsupported signature")
	}
	key, err := v.keyFor(ctx, kid)
	if err != nil {
		return nil, &IDJAGError{Code: "temporarily_unavailable", Message: "the identity provider's keys could not be read: " + err.Error()}
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if key == nil || err != nil || !mcpVerifySignature(parts[0]+"."+parts[1], sig, alg, key) {
		return nil, bad("signature does not verify")
	}
	now := time.Now().Unix()
	skew := int64(v.cfg.ClockSkew / time.Second)
	var auds []interface{}
	if list, ok := c["aud"].([]interface{}); ok {
		auds = list
	} else {
		auds = []interface{}{c["aud"]}
	}
	exp, _ := c["exp"].(float64)
	iat, _ := c["iat"].(float64)
	sub, _ := c["sub"].(string)
	jti, _ := c["jti"].(string)
	switch {
	case c["iss"] != v.cfg.Issuer:
		return nil, bad("another issuer")
	case len(auds) != 1 || auds[0] != v.cfg.Audience:
		return nil, bad("not for this authorization server")
	case c["client_id"] != clientID || clientID == "":
		return nil, bad("issued to another client")
	case exp == 0 || int64(exp)+skew < now:
		return nil, bad("expired")
	case iat == 0 || int64(iat)-skew > now:
		return nil, bad("issued in the future")
	case sub == "" || jti == "":
		return nil, bad("sub and jti are required")
	}
	first := v.cfg.FirstUse
	if first == nil {
		first = v.rememberOnce
	}
	if !first(jti, int64(exp)) {
		return nil, bad("already used")
	}
	out := &IDJAGClaims{Iss: v.cfg.Issuer, Sub: sub, Aud: v.cfg.Audience, ClientID: clientID, JTI: jti, IssuedAt: int64(iat), ExpiresAt: int64(exp), Scopes: []string{}, Claims: c}
	if s, _ := c["scope"].(string); s != "" {
		out.Scopes = strings.Split(s, " ")
	}
	out.Resource, _ = c["resource"].(string)
	out.Tenant, _ = c["tenant"].(string)
	out.Email, _ = c["email"].(string)
	if at, ok := c["auth_time"].(float64); ok {
		out.AuthTime = int64(at)
	}
	if amr, ok := c["amr"].([]interface{}); ok {
		for _, a := range amr {
			if s, ok := a.(string); ok {
				out.AMR = append(out.AMR, s)
			}
		}
	}
	return out, nil
}

func xaaSafeURL(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil {
		return false
	}
	host := u.Hostname()
	return u.Scheme == "https" || (u.Scheme == "http" && (host == "localhost" || host == "127.0.0.1" || host == "::1"))
}

func xaaPostForm(ctx context.Context, client *http.Client, target string, form url.Values, id, secret string) (map[string]interface{}, error) {
	if !xaaSafeURL(target) {
		return nil, fmt.Errorf("touchque: %s must be an https URL", target)
	}
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	}
	req, err := http.NewRequestWithContext(ctx, "POST", target, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	if secret != "" {
		req.SetBasicAuth(url.QueryEscape(id), url.QueryEscape(secret))
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	data := map[string]interface{}{}
	_ = json.NewDecoder(resp.Body).Decode(&data)
	if resp.StatusCode >= 400 {
		code, _ := data["error"].(string)
		msg, _ := data["error_description"].(string)
		if code == "" {
			code = "server_error"
		}
		if msg == "" {
			msg = fmt.Sprintf("%s answered %d", target, resp.StatusCode)
		}
		return nil, &IDJAGError{Code: code, Message: msg, Status: resp.StatusCode}
	}
	return data, nil
}

// RequestIDJAGParams: the identity provider (Issuer, or TokenEndpoint), your app there and its
// secret, the member's ID token, and the other service's authorization server (Audience).
type RequestIDJAGParams struct {
	Issuer        string
	TokenEndpoint string
	ClientID      string
	ClientSecret  string
	IDToken       string
	Audience      string
	Resource      string
	Scope         string
	HTTPClient    *http.Client
}

// IDJAG is the grant the identity provider issued.
type IDJAG struct {
	Assertion string
	ExpiresIn int
	Scope     string
}

// RequestIDJAG trades a member's ID token for an ID-JAG (token exchange, client_secret_basic).
func RequestIDJAG(ctx context.Context, p RequestIDJAGParams) (*IDJAG, error) {
	endpoint := p.TokenEndpoint
	if endpoint == "" {
		if p.Issuer == "" {
			return nil, errors.New("touchque: RequestIDJAG needs Issuer or TokenEndpoint")
		}
		client := p.HTTPClient
		if client == nil {
			client = &http.Client{Timeout: 5 * time.Second}
		}
		meta, err := xaaDiscover(ctx, client, p.Issuer)
		if err != nil {
			return nil, err
		}
		endpoint, _ = meta["token_endpoint"].(string)
		if endpoint == "" {
			return nil, errors.New("touchque: the identity provider names no token_endpoint")
		}
	}
	form := url.Values{"grant_type": {TokenExchangeGrant}, "requested_token_type": {IDJAGTokenType}, "subject_token": {p.IDToken},
		"subject_token_type": {IDTokenTokenType}, "audience": {p.Audience}}
	if p.Resource != "" {
		form.Set("resource", p.Resource)
	}
	if p.Scope != "" {
		form.Set("scope", p.Scope)
	}
	data, err := xaaPostForm(ctx, p.HTTPClient, endpoint, form, p.ClientID, p.ClientSecret)
	if err != nil {
		return nil, err
	}
	assertion, _ := data["access_token"].(string)
	if data["issued_token_type"] != IDJAGTokenType || assertion == "" {
		return nil, &IDJAGError{Code: "invalid_response", Message: "the identity provider did not answer with an ID-JAG"}
	}
	out := &IDJAG{Assertion: assertion}
	if n, ok := data["expires_in"].(float64); ok {
		out.ExpiresIn = int(n)
	}
	out.Scope, _ = data["scope"].(string)
	return out, nil
}

// RedeemIDJAGParams: the other service's token endpoint, your client there, the ID-JAG.
type RedeemIDJAGParams struct {
	TokenEndpoint string
	ClientID      string
	ClientSecret  string
	Assertion     string
	Resource      string
	Scope         string
	HTTPClient    *http.Client
}

// RedeemIDJAG trades an ID-JAG for an access token at the other service (jwt-bearer).
func RedeemIDJAG(ctx context.Context, p RedeemIDJAGParams) (map[string]interface{}, error) {
	form := url.Values{"grant_type": {JWTBearerGrant}, "assertion": {p.Assertion}}
	if p.ClientSecret == "" {
		form.Set("client_id", p.ClientID)
	}
	if p.Resource != "" {
		form.Set("resource", p.Resource)
	}
	if p.Scope != "" {
		form.Set("scope", p.Scope)
	}
	return xaaPostForm(ctx, p.HTTPClient, p.TokenEndpoint, form, p.ClientID, p.ClientSecret)
}
