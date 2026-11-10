package touchque

// TouchQue Login (hosted sign-in) for your app: an OpenID Connect client for
// your tenant (acme.login.touchque.com or your own domain).
//
//	login, _ := touchque.NewHostedLogin(touchque.HostedLoginConfig{Domain: "acme.login.touchque.com", ClientID: id, ClientSecret: secret, RedirectURI: cb})
//	req, _ := login.AuthorizationURL(touchque.AuthorizationOptions{})   // keep req.State, req.Nonce, req.CodeVerifier; redirect to req.URL
//	tokens, err := login.HandleCallback(ctx, r.URL.Query(), touchque.CallbackChecks{State: ..., Nonce: ..., CodeVerifier: ...})
//	tokens.Claims["sub"], tokens.AccessToken, tokens.RefreshToken
//
// PKCE (S256) is always used. ID tokens are checked against the tenant's JWKS
// (RS256 signature, issuer, audience, expiry, nonce, at_hash). Your API
// checks access tokens with VerifyAccessToken.
//
// An app acting for a user (an AI agent; a confidential app whose grantTypes
// list the grant, and an API that grants it scopes):
//
//	forAda, _ := login.ExchangeToken(ctx, adasAccessToken, "https://api.acme.com", "")    // RFC 8693
//	ask, _ := login.AskUser(ctx, touchque.AskUserParams{LoginHint: "ada@acme.com", Scope: "openid payments:create", BindingMessage: "Pay invoice 42"})
//	// show ask.BindingCode in the conversation
//	approved, err := login.WaitForUser(ctx, ask)                                         // CIBA, poll mode

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

// HostedLoginError is a failed sign-in or token check; Code is machine-readable.
type HostedLoginError struct {
	Code        string
	Description string
	Status      int
}

func (e *HostedLoginError) Error() string {
	if e.Description != "" {
		return e.Code + ": " + e.Description
	}
	return e.Code
}

func loginErr(code, desc string) *HostedLoginError {
	return &HostedLoginError{Code: code, Description: desc}
}

// HostedLoginConfig configures a HostedLogin.
type HostedLoginConfig struct {
	// Domain is the tenant's sign-in domain (acme.login.touchque.com) or full issuer URL.
	Domain   string
	ClientID string
	// ClientSecret: apps with a server. SPAs and native apps leave it empty.
	ClientSecret string
	RedirectURI  string
	// Scope defaults to "openid profile email". Add offline_access for a refresh token.
	Scope string
	// Audience is your API's identifier, to get an access token for it.
	Audience string
	// ClockTolerance defaults to 60 seconds.
	ClockTolerance time.Duration
	HTTPClient     *http.Client
}

// AuthorizationOptions are the optional /authorize parameters.
type AuthorizationOptions struct {
	State, Nonce, CodeVerifier, RedirectURI, Scope, Audience string
	// Prompt: "login", "none", "consent", "select_account" or "create".
	Prompt string
	// LoginHint pre-fills the email; ScreenHint "signup" opens the sign-up page.
	LoginHint, ScreenHint, UILocales string
	// MaxAge in seconds; 0 means not sent, and a negative value sends
	// max_age=0: sign in again now (a step-up, see MyAccountError.StepUp).
	MaxAge                               int
	Connection, Organization, Invitation string
	ACRValues, ResponseMode              string
	ExtraParams                          map[string]string
}

// AuthorizationRequest is the URL to send the browser to and what to keep until the callback.
type AuthorizationRequest struct {
	URL, State, Nonce, CodeVerifier string
}

// CallbackChecks are the values kept from AuthorizationURL.
type CallbackChecks struct {
	State, Nonce, CodeVerifier string
	RedirectURI                string
	// MaxAge rejects sign-ins older than this many seconds (0: no check;
	// negative: the sign-in must be new, as asked with max_age=0).
	MaxAge int
}

// TokenSet is what the token endpoint returned; Claims are the verified ID token's.
type TokenSet struct {
	AccessToken  string
	TokenType    string
	ExpiresAt    time.Time
	Scope        string
	IDToken      string
	RefreshToken string
	Claims       map[string]interface{}
	// AuthorizationDetails is what the user approved on the phone (CIBA).
	AuthorizationDetails []map[string]interface{}
	// IssuedTokenType is set by token exchange (the access token type).
	IssuedTokenType string
	// Connection is set by GetConnectionToken: the connection the provider token is for.
	Connection string
}

// ConnectionTokenType is the requested_token_type of the token vault (GetConnectionToken).
const ConnectionTokenType = "urn:touchque:params:oauth:token-type:connection-access-token"

// AskUserParams is a CIBA request: at least one of BindingMessage (at most
// 64 characters) and AuthorizationDetails (RFC 9396) says what it is for.
type AskUserParams struct {
	LoginHint            string // the user's e-mail or usr_ id
	Scope                string
	Audience             string
	BindingMessage       string
	AuthorizationDetails []map[string]interface{}
	RequestedExpiry      int // seconds, 30 to 300 (default 300)
}

// UserApprovalRequest is a pending CIBA request: show BindingCode, then WaitForUser.
type UserApprovalRequest struct {
	AuthReqID   string
	ExpiresAt   time.Time
	Interval    time.Duration
	BindingCode string
}

// HostedLogin is an OpenID Connect client for one TouchQue Login tenant.
type HostedLogin struct {
	Issuer string
	cfg    HostedLoginConfig
	http   *http.Client
	mu     sync.Mutex
	keys   map[string]*rsa.PublicKey
	keysAt time.Time
}

// NewHostedLogin checks the configuration. Domain must be https://, except
// on this machine (localhost, 127.0.0.1, ::1, *.localhost).
func NewHostedLogin(cfg HostedLoginConfig) (*HostedLogin, error) {
	if cfg.Domain == "" {
		return nil, loginErr("config", "Domain is required")
	}
	if cfg.ClientID == "" {
		return nil, loginErr("config", "ClientID is required")
	}
	issuer := strings.TrimRight(cfg.Domain, "/")
	if !strings.HasPrefix(issuer, "http://") && !strings.HasPrefix(issuer, "https://") {
		issuer = "https://" + issuer
	}
	// Codes, PKCE verifiers, the client secret and every token go to the
	// issuer: plaintext http only on this machine, as for the API BaseURL.
	u, err := url.Parse(issuer)
	if err != nil || u.Hostname() == "" {
		return nil, loginErr("config", "Domain is not a valid URL")
	}
	if host := strings.ToLower(u.Hostname()); u.Scheme == "http" && !localHosts[host] && !strings.HasSuffix(host, ".localhost") {
		return nil, loginErr("config", fmt.Sprintf("refusing a plaintext http:// Domain for %q: use https://", u.Hostname()))
	}
	if cfg.Scope == "" {
		cfg.Scope = "openid profile email"
	}
	if cfg.ClockTolerance == 0 {
		cfg.ClockTolerance = 60 * time.Second
	}
	client := cfg.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}
	return &HostedLogin{Issuer: issuer, cfg: cfg, http: client}, nil
}

func randomString(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return b64u(b)
}

func eq(a, b string) bool { return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1 }

// AuthorizationURL builds the /authorize URL with PKCE S256, state and nonce.
func (l *HostedLogin) AuthorizationURL(o AuthorizationOptions) (*AuthorizationRequest, error) {
	redirect := o.RedirectURI
	if redirect == "" {
		redirect = l.cfg.RedirectURI
	}
	if redirect == "" {
		return nil, loginErr("config", "RedirectURI is required")
	}
	state, nonce, verifier := o.State, o.Nonce, o.CodeVerifier
	if state == "" {
		state = randomString(32)
	}
	if nonce == "" {
		nonce = randomString(32)
	}
	if verifier == "" {
		verifier = randomString(48)
	}
	sum := sha256.Sum256([]byte(verifier))
	scope := o.Scope
	if scope == "" {
		scope = l.cfg.Scope
	}
	q := url.Values{
		"response_type":         {"code"},
		"client_id":             {l.cfg.ClientID},
		"redirect_uri":          {redirect},
		"scope":                 {scope},
		"state":                 {state},
		"nonce":                 {nonce},
		"code_challenge":        {b64u(sum[:])},
		"code_challenge_method": {"S256"},
	}
	audience := o.Audience
	if audience == "" {
		audience = l.cfg.Audience
	}
	set := func(k, v string) {
		if v != "" {
			q.Set(k, v)
		}
	}
	set("audience", audience)
	set("prompt", o.Prompt)
	set("login_hint", o.LoginHint)
	set("screen_hint", o.ScreenHint)
	set("ui_locales", o.UILocales)
	switch {
	case o.MaxAge > 0:
		q.Set("max_age", strconv.Itoa(o.MaxAge))
	case o.MaxAge < 0:
		q.Set("max_age", "0")
	}
	set("connection", o.Connection)
	set("organization", o.Organization)
	set("invitation", o.Invitation)
	set("acr_values", o.ACRValues)
	set("response_mode", o.ResponseMode)
	for k, v := range o.ExtraParams {
		q.Set(k, v)
	}
	return &AuthorizationRequest{URL: l.Issuer + "/authorize?" + q.Encode(), State: state, Nonce: nonce, CodeVerifier: verifier}, nil
}

// HandleCallback checks state (and iss), exchanges the code with the PKCE
// verifier and verifies the ID token. params is r.URL.Query() (or r.PostForm
// for response_mode=form_post).
func (l *HostedLogin) HandleCallback(ctx context.Context, params url.Values, c CallbackChecks) (*TokenSet, error) {
	got := params.Get("state")
	if got == "" || c.State == "" || !eq(got, c.State) {
		return nil, loginErr("state_mismatch", "The state does not match this sign-in")
	}
	// RFC 9207: a response that carries iss (even an empty one) must name this issuer,
	// the one the ID token is checked against. Servers that do not send iss yet are accepted.
	if params.Has("iss") && params.Get("iss") != l.Issuer {
		if iss := params.Get("iss"); iss != "" {
			return nil, loginErr("issuer_mismatch", "The response came from "+iss)
		}
		return nil, loginErr("issuer_mismatch", "The response has an empty iss")
	}
	if e := params.Get("error"); e != "" {
		return nil, loginErr(e, params.Get("error_description"))
	}
	code := params.Get("code")
	if code == "" {
		return nil, loginErr("invalid_request", "The callback has no code")
	}
	redirect := c.RedirectURI
	if redirect == "" {
		redirect = l.cfg.RedirectURI
	}
	tokens, err := l.token(ctx, url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {redirect}, "code_verifier": {c.CodeVerifier}})
	if err != nil {
		return nil, err
	}
	if tokens.IDToken == "" {
		return nil, loginErr("invalid_token", "No ID token: ask for the openid scope")
	}
	claims, err := l.VerifyIDToken(ctx, tokens.IDToken, c.Nonce, tokens.AccessToken, c.MaxAge)
	if err != nil {
		return nil, err
	}
	tokens.Claims = claims
	return tokens, nil
}

// Refresh returns a new access token and a rotated refresh token: keep the new one.
func (l *HostedLogin) Refresh(ctx context.Context, refreshToken string) (*TokenSet, error) {
	tokens, err := l.token(ctx, url.Values{"grant_type": {"refresh_token"}, "refresh_token": {refreshToken}})
	if err != nil {
		return nil, err
	}
	if tokens.IDToken != "" {
		if tokens.Claims, err = l.VerifyIDToken(ctx, tokens.IDToken, "", tokens.AccessToken, 0); err != nil {
			return nil, err
		}
	}
	return tokens, nil
}

// ClientCredentials gets a machine-to-machine access token for your API.
func (l *HostedLogin) ClientCredentials(ctx context.Context, audience, scope string) (*TokenSet, error) {
	f := url.Values{"grant_type": {"client_credentials"}, "audience": {audience}}
	if scope != "" {
		f.Set("scope", scope)
	}
	return l.token(ctx, f)
}

// ExchangeToken (RFC 8693) trades a signed-in user's access token for one to
// call audience on their behalf (sub = the user, act.sub = this app). For a
// confidential app the API grants scopes to; never longer than the user's token.
func (l *HostedLogin) ExchangeToken(ctx context.Context, subjectToken, audience, scope string) (*TokenSet, error) {
	f := url.Values{
		"grant_type": {"urn:ietf:params:oauth:grant-type:token-exchange"}, "subject_token": {subjectToken},
		"subject_token_type": {"urn:ietf:params:oauth:token-type:access_token"}, "audience": {audience},
	}
	if scope != "" {
		f.Set("scope", scope)
	}
	return l.token(ctx, f)
}

// GetConnectionToken (token vault) returns the provider's own access token
// (Google, Microsoft, GitHub…) for the signed-in user, from a connection that
// stores tokens. TouchQue refreshes it; the refresh token never leaves.
// userAccessToken is the user's token for this app (or for an app the
// connection lists). A HostedLoginError invalid_grant means the user has not
// signed in with the connection since it started storing tokens, or they
// stopped app access.
func (l *HostedLogin) GetConnectionToken(ctx context.Context, userAccessToken, connection, scope string) (*TokenSet, error) {
	f := url.Values{
		"grant_type": {"urn:ietf:params:oauth:grant-type:token-exchange"}, "subject_token": {userAccessToken},
		"subject_token_type":   {"urn:ietf:params:oauth:token-type:access_token"},
		"requested_token_type": {ConnectionTokenType}, "connection": {connection},
	}
	if scope != "" {
		f.Set("scope", scope)
	}
	return l.token(ctx, f)
}

// AskUser (CIBA) asks the user to approve on their phone.
func (l *HostedLogin) AskUser(ctx context.Context, p AskUserParams) (*UserApprovalRequest, error) {
	f := url.Values{"login_hint": {p.LoginHint}, "scope": {p.Scope}}
	if p.Audience != "" {
		f.Set("audience", p.Audience)
	}
	if p.BindingMessage != "" {
		f.Set("binding_message", p.BindingMessage)
	}
	if len(p.AuthorizationDetails) > 0 {
		b, _ := json.Marshal(p.AuthorizationDetails)
		f.Set("authorization_details", string(b))
	}
	if p.RequestedExpiry > 0 {
		f.Set("requested_expiry", strconv.Itoa(p.RequestedExpiry))
	}
	res, body, err := l.post(ctx, "/bc-authorize", f)
	if err != nil {
		return nil, err
	}
	if res.StatusCode >= 400 {
		return nil, oauthError(res.StatusCode, body)
	}
	var d struct {
		AuthReqID   string `json:"auth_req_id"`
		ExpiresIn   int    `json:"expires_in"`
		Interval    *int   `json:"interval"`
		BindingCode string `json:"binding_code"`
	}
	if err := json.Unmarshal(body, &d); err != nil {
		return nil, loginErr("invalid_response", "bc-authorize did not answer JSON")
	}
	interval := 5
	if d.Interval != nil {
		interval = *d.Interval
	}
	return &UserApprovalRequest{AuthReqID: d.AuthReqID, ExpiresAt: time.Now().Add(time.Duration(d.ExpiresIn) * time.Second), Interval: time.Duration(interval) * time.Second, BindingCode: d.BindingCode}, nil
}

// WaitForUser polls until the user answers: the tokens, or a
// *HostedLoginError with Code access_denied or expired_token.
func (l *HostedLogin) WaitForUser(ctx context.Context, r *UserApprovalRequest) (*TokenSet, error) {
	interval := r.Interval
	for {
		if time.Now().After(r.ExpiresAt) {
			return nil, loginErr("expired_token", "The user did not answer in time")
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(interval):
		}
		tokens, err := l.token(ctx, url.Values{"grant_type": {"urn:openid:params:grant-type:ciba"}, "auth_req_id": {r.AuthReqID}})
		if err == nil {
			return tokens, nil
		}
		var e *HostedLoginError
		if !errors.As(err, &e) {
			return nil, err
		}
		switch e.Code {
		case "authorization_pending":
		case "slow_down":
			interval += 5 * time.Second
		default:
			return nil, err
		}
	}
}

// Revoke ends a refresh token and its rotated family.
func (l *HostedLogin) Revoke(ctx context.Context, token string) error {
	res, body, err := l.post(ctx, "/oauth/revoke", url.Values{"token": {token}})
	if err != nil {
		return err
	}
	if res.StatusCode >= 400 {
		return oauthError(res.StatusCode, body)
	}
	return nil
}

// Userinfo returns the signed-in user's claims for an access token.
func (l *HostedLogin) Userinfo(ctx context.Context, accessToken string) (map[string]interface{}, error) {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, l.Issuer+"/userinfo", nil)
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Accept", "application/json")
	res, err := l.http.Do(req)
	if err != nil {
		return nil, &NetworkError{Message: err.Error()}
	}
	defer res.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(res.Body, 1<<20))
	if res.StatusCode >= 400 {
		return nil, oauthError(res.StatusCode, body)
	}
	var out map[string]interface{}
	return out, json.Unmarshal(body, &out)
}

// LogoutURL is where to send the browser to sign out of the hosted pages too.
func (l *HostedLogin) LogoutURL(idTokenHint, postLogoutRedirectURI, state string) string {
	q := url.Values{"client_id": {l.cfg.ClientID}}
	if idTokenHint != "" {
		q.Set("id_token_hint", idTokenHint)
	}
	if postLogoutRedirectURI != "" {
		q.Set("post_logout_redirect_uri", postLogoutRedirectURI)
	}
	if state != "" {
		q.Set("state", state)
	}
	return l.Issuer + "/oidc/logout?" + q.Encode()
}

// VerifyAccessToken is for your API: signature, issuer, audience, expiry, typ at+jwt, scopes.
func (l *HostedLogin) VerifyAccessToken(ctx context.Context, token, audience string, requiredScopes ...string) (map[string]interface{}, error) {
	payload, err := l.verifyJWT(ctx, token, "at+jwt")
	if err != nil {
		return nil, err
	}
	if !hasAudience(payload["aud"], audience) {
		return nil, loginErr("invalid_token", "The token is for another audience")
	}
	scope, _ := payload["scope"].(string)
	have := map[string]bool{}
	for _, s := range strings.Fields(scope) {
		have[s] = true
	}
	var missing []string
	for _, s := range requiredScopes {
		if !have[s] {
			missing = append(missing, s)
		}
	}
	if len(missing) > 0 {
		return nil, &HostedLoginError{Code: "insufficient_scope", Description: "Missing scope: " + strings.Join(missing, " "), Status: 403}
	}
	return payload, nil
}

// VerifyIDToken checks an ID token of this tenant for this app. nonce and
// accessToken are checked when not empty; maxAge when not 0 (negative: a
// sign-in just now, within the clock tolerance).
func (l *HostedLogin) VerifyIDToken(ctx context.Context, idToken, nonce, accessToken string, maxAge int) (map[string]interface{}, error) {
	payload, err := l.verifyJWT(ctx, idToken, "")
	if err != nil {
		return nil, err
	}
	if !hasAudience(payload["aud"], l.cfg.ClientID) {
		return nil, loginErr("invalid_token", "The ID token is for another app")
	}
	if auds, ok := payload["aud"].([]interface{}); ok && len(auds) > 1 && payload["azp"] != l.cfg.ClientID {
		return nil, loginErr("invalid_token", "azp does not name this app")
	}
	if nonce != "" {
		got, _ := payload["nonce"].(string)
		if !eq(got, nonce) {
			return nil, loginErr("nonce_mismatch", "The nonce does not match this sign-in")
		}
	}
	if atHash, ok := payload["at_hash"].(string); ok && accessToken != "" {
		sum := sha256.Sum256([]byte(accessToken))
		if !eq(atHash, b64u(sum[:16])) {
			return nil, loginErr("invalid_token", "at_hash does not match the access token")
		}
	}
	if authTime, ok := payload["auth_time"].(float64); ok && maxAge != 0 {
		if time.Since(time.Unix(int64(authTime), 0)) > time.Duration(max(maxAge, 0))*time.Second+l.cfg.ClockTolerance {
			return nil, loginErr("login_required", "The sign-in is older than maxAge")
		}
	}
	return payload, nil
}

func hasAudience(aud interface{}, want string) bool {
	switch v := aud.(type) {
	case string:
		return v == want
	case []interface{}:
		for _, a := range v {
			if s, ok := a.(string); ok && s == want {
				return true
			}
		}
	}
	return false
}

func oauthError(status int, body []byte) *HostedLoginError {
	var d struct {
		Error            string `json:"error"`
		ErrorDescription string `json:"error_description"`
	}
	_ = json.Unmarshal(body, &d)
	if d.Error == "" {
		d.Error = fmt.Sprintf("http_%d", status)
	}
	return &HostedLoginError{Code: d.Error, Description: d.ErrorDescription, Status: status}
}

func (l *HostedLogin) post(ctx context.Context, path string, form url.Values) (*http.Response, []byte, error) {
	if l.cfg.ClientSecret == "" {
		form.Set("client_id", l.cfg.ClientID)
	}
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, l.Issuer+path, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	if l.cfg.ClientSecret != "" {
		req.SetBasicAuth(url.QueryEscape(l.cfg.ClientID), url.QueryEscape(l.cfg.ClientSecret))
	}
	res, err := l.http.Do(req)
	if err != nil {
		return nil, nil, &NetworkError{Message: err.Error()}
	}
	defer res.Body.Close()
	body, err := io.ReadAll(io.LimitReader(res.Body, 1<<20))
	return res, body, err
}

func (l *HostedLogin) token(ctx context.Context, form url.Values) (*TokenSet, error) {
	res, body, err := l.post(ctx, "/oauth/token", form)
	if err != nil {
		return nil, err
	}
	if res.StatusCode >= 400 {
		return nil, oauthError(res.StatusCode, body)
	}
	var d struct {
		AccessToken  string                   `json:"access_token"`
		TokenType    string                   `json:"token_type"`
		ExpiresIn    int                      `json:"expires_in"`
		Scope        string                   `json:"scope"`
		IDToken      string                   `json:"id_token"`
		RefreshToken string                   `json:"refresh_token"`
		Details      []map[string]interface{} `json:"authorization_details"`
		IssuedType   string                   `json:"issued_token_type"`
		Connection   string                   `json:"connection"`
	}
	if err := json.Unmarshal(body, &d); err != nil {
		return nil, loginErr("invalid_response", "The token endpoint did not answer JSON")
	}
	return &TokenSet{AccessToken: d.AccessToken, TokenType: d.TokenType, ExpiresAt: time.Now().Add(time.Duration(d.ExpiresIn) * time.Second), Scope: d.Scope, IDToken: d.IDToken, RefreshToken: d.RefreshToken, AuthorizationDetails: d.Details, IssuedTokenType: d.IssuedType, Connection: d.Connection}, nil
}

func (l *HostedLogin) loadKeys(ctx context.Context, force bool) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	age := time.Since(l.keysAt)
	if !force && len(l.keys) > 0 && age < time.Hour {
		return nil
	}
	if force && age < 30*time.Second {
		return nil
	}
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, l.Issuer+"/.well-known/jwks.json", nil)
	req.Header.Set("Accept", "application/json")
	res, err := l.http.Do(req)
	if err != nil {
		return &NetworkError{Message: err.Error()}
	}
	defer res.Body.Close()
	if res.StatusCode >= 400 {
		return loginErr("jwks_unavailable", fmt.Sprintf("JWKS answered %d", res.StatusCode))
	}
	var set struct {
		Keys []struct {
			Kty, Kid, N, E, Use string
		} `json:"keys"`
	}
	if err := json.NewDecoder(io.LimitReader(res.Body, 1<<20)).Decode(&set); err != nil {
		return loginErr("jwks_unavailable", "JWKS is not JSON")
	}
	keys := map[string]*rsa.PublicKey{}
	for _, k := range set.Keys {
		if k.Kty != "RSA" || k.Kid == "" || (k.Use != "" && k.Use != "sig") {
			continue
		}
		n, err1 := base64.RawURLEncoding.DecodeString(k.N)
		e, err2 := base64.RawURLEncoding.DecodeString(k.E)
		if err1 != nil || err2 != nil || len(e) > 4 {
			continue
		}
		keys[k.Kid] = &rsa.PublicKey{N: new(big.Int).SetBytes(n), E: int(new(big.Int).SetBytes(e).Int64())}
	}
	l.keys = keys
	l.keysAt = time.Now()
	return nil
}

func (l *HostedLogin) verifyJWT(ctx context.Context, token, typ string) (map[string]interface{}, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, loginErr("invalid_token", "not a JWT")
	}
	var header struct{ Alg, Typ, Kid string }
	hb, err1 := base64.RawURLEncoding.DecodeString(parts[0])
	pb, err2 := base64.RawURLEncoding.DecodeString(parts[1])
	sig, err3 := base64.RawURLEncoding.DecodeString(parts[2])
	if err1 != nil || err2 != nil || err3 != nil || json.Unmarshal(hb, &header) != nil {
		return nil, loginErr("invalid_token", "malformed JWT")
	}
	if header.Alg != "RS256" {
		return nil, loginErr("invalid_token", "Unexpected alg "+header.Alg)
	}
	if typ != "" && strings.ToLower(header.Typ) != typ {
		return nil, loginErr("invalid_token", "Wrong token type")
	}
	if err := l.loadKeys(ctx, false); err != nil {
		return nil, err
	}
	l.mu.Lock()
	key := l.keys[header.Kid]
	l.mu.Unlock()
	if key == nil {
		if err := l.loadKeys(ctx, true); err != nil {
			return nil, err
		}
		l.mu.Lock()
		key = l.keys[header.Kid]
		l.mu.Unlock()
	}
	if key == nil {
		return nil, loginErr("invalid_token", "Unknown signing key")
	}
	sum := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if rsa.VerifyPKCS1v15(key, crypto.SHA256, sum[:], sig) != nil {
		return nil, loginErr("invalid_token", "Bad signature")
	}
	var payload map[string]interface{}
	if err := json.Unmarshal(pb, &payload); err != nil {
		return nil, loginErr("invalid_token", "malformed JWT")
	}
	now := time.Now()
	if payload["iss"] != l.Issuer {
		return nil, loginErr("invalid_token", "Wrong issuer")
	}
	exp, ok := payload["exp"].(float64)
	if !ok || now.After(time.Unix(int64(exp), 0).Add(l.cfg.ClockTolerance)) {
		return nil, loginErr("invalid_token", "The token expired")
	}
	if iat, ok := payload["iat"].(float64); ok && time.Unix(int64(iat), 0).After(now.Add(l.cfg.ClockTolerance)) {
		return nil, loginErr("invalid_token", "The token is from the future")
	}
	return payload, nil
}
