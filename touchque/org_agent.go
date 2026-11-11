package touchque

// An organization's AI agent on Touchque SSO (Organization → AI agents in
// the dashboard): it gets 5-minute tokens for one of the organization's apps,
// proving who it is with its own key (private_key_jwt) or with the token its
// platform already gives it (GitHub Actions, GitLab, Google Cloud, Azure,
// Kubernetes), and binds each token to a DPoP key made when it starts. The app
// checks the token with Touchque's JWKS and the DPoP proof on every call.
//
//	agent, _ := touchque.NewOrgAgent(touchque.OrgAgentConfig{AgentID: "oagt_…", PrivateKey: os.Getenv("TQ_ORG_AGENT_KEY")})
//	req, _ := http.NewRequest("GET", "https://payments.acme.com/invoices", nil)
//	_ = agent.Authorize(req, "tqapp_…", "")
//
//	// In a GitHub Actions job (permissions: id-token: write), with no key to store:
//	agent, _ := touchque.NewOrgAgent(touchque.OrgAgentConfig{AgentID: "oagt_…", Assertion: touchque.GitHubActionsToken("touchque")})
//
// Acting for a member, when its admin allowed it (Organization → AI agents → Access):
//
//	t, _ := agent.ExchangeToken(membersAccessToken, "tqapp_…", "")                // RFC 8693
//	google, _ := agent.GetConnectionToken(membersAccessToken, "google", "")         // token vault
//	ask, _ := agent.AskToOpenSharedAccount("k3J…", "ada@acme.com", "Post the launch photo") // the member's extension signs in
//	result, _ := agent.WaitForSharedAccount(ctx, ask)                              // opened | refused | declined | expired
//	ask, _ := agent.AskMember(touchque.AskMemberParams{LoginHint: "ada@acme.com", BindingMessage: "Pay invoice 42"})
//	// show ask.BindingCode in the conversation
//	approved, _ := agent.WaitForMember(ctx, ask)                                 // CIBA, poll mode

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"
)

var orgAgentIDPattern = regexp.MustCompile(`^oagt_[a-z2-9]{20}$`)

// OrgAgentConfig configures an organization's AI agent.
type OrgAgentConfig struct {
	// AgentID: the oagt_… id; default TQ_ORG_AGENT_ID.
	AgentID string
	// Issuer: Touchque SSO; default TQ_SSO_URL or https://sso.touchque.com.
	Issuer string
	// PrivateKey: its own key (a JWK map or JSON, a PEM, or a Go private key); default TQ_ORG_AGENT_KEY.
	PrivateKey interface{}
	Kid        string
	// Assertion: instead of a key, the platform's token, asked for each time a token is needed.
	Assertion func() (string, error)
	// Resource and Scope used when a call does not name them.
	Resource  string
	Scope     string
	TimeoutMs int
}

// OrgAgentToken is a DPoP-bound access token for one app.
type OrgAgentToken struct {
	AccessToken string
	TokenType   string
	ExpiresIn   int
	Scope       string
	// AuthorizationDetails: with CIBA, exactly what the member approved on the phone.
	AuthorizationDetails []map[string]interface{}
}

// OrgAgentConnectionToken is a member's own access token at another service
// (the token vault): a Bearer token for that service's API.
type OrgAgentConnectionToken struct {
	AccessToken string
	TokenType   string
	// ExpiresIn is 0 when the service does not say.
	ExpiresIn  int
	Scope      string
	Connection string
}

// SharedAccountAsk is an agent's ask to open a shared account for a member.
type SharedAccountAsk struct {
	AskID string
	// OpenURL is the page the member opens in the browser where their Touchque extension is paired.
	OpenURL   string
	Status    string
	ExpiresIn int
}

// SharedAccountAskStatus says where an ask stands: waiting_member, asked_phone,
// opened, refused, declined or expired; Reason says why it was refused.
type SharedAccountAskStatus struct {
	Status   string
	Reason   string
	CaseCode string
}

// AskMemberParams asks a member to approve on their phone (CIBA).
type AskMemberParams struct {
	// LoginHint: the member's e-mail.
	LoginHint string
	// BindingMessage: up to 64 characters, shown on the phone marked unverified.
	BindingMessage string
	// AuthorizationDetails: RFC 9396 details the phone shows.
	AuthorizationDetails []map[string]interface{}
	Resource             string
	Scope                string
	// RequestedExpiry in seconds (30-600); the push lives at most as long as Touchque lets it.
	RequestedExpiry int
}

// MemberRequest is a CIBA request waiting for the member.
type MemberRequest struct {
	AuthReqID string
	ExpiresIn int
	Interval  int
	// BindingCode: show it in the conversation; the member picks it on the phone.
	BindingCode string
}

const (
	cibaGrant           = "urn:openid:params:grant-type:ciba"
	tokenExchangeGrant  = "urn:ietf:params:oauth:grant-type:token-exchange"
	accessTokenType     = "urn:ietf:params:oauth:token-type:access_token"
	connectionTokenType = "urn:touchque:params:oauth:token-type:connection-access-token"
)

type orgAgentCached struct {
	token     *OrgAgentToken
	expiresAt time.Time
}

// OrgAgent is an organization's AI agent client.
type OrgAgent struct {
	AgentID   string
	issuer    string
	identity  *Agent // signs its assertions; nil with Assertion
	assertion func() (string, error)
	dpopKey   *Agent // the DPoP key, made here
	resource  string
	scope     string
	client    *http.Client

	mu     sync.Mutex
	tokens map[string]orgAgentCached
}

// GitHubActionsToken is the token a GitHub Actions job may ask for (the job needs `permissions: id-token: write`).
func GitHubActionsToken(audience string) func() (string, error) {
	return func() (string, error) {
		target, bearer := os.Getenv("ACTIONS_ID_TOKEN_REQUEST_URL"), os.Getenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN")
		if target == "" || bearer == "" {
			return "", &ConfigError{Message: "not in a GitHub Actions job with `permissions: id-token: write`"}
		}
		u, err := url.Parse(target)
		if err != nil {
			return "", err
		}
		q := u.Query()
		q.Set("audience", audience)
		u.RawQuery = q.Encode()
		req, _ := http.NewRequest("GET", u.String(), nil)
		req.Header.Set("Authorization", "Bearer "+bearer)
		resp, err := (&http.Client{Timeout: 10 * time.Second}).Do(req)
		if err != nil {
			return "", &NetworkError{Message: "GitHub token request failed: " + err.Error()}
		}
		defer resp.Body.Close()
		var data struct {
			Value string `json:"value"`
		}
		if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&data); err != nil || data.Value == "" {
			return "", &ConfigError{Message: "GitHub gave no token"}
		}
		return data.Value, nil
	}
}

// FileToken reads a token the platform writes to a file and renews (a Kubernetes projected service account token…).
func FileToken(path string) func() (string, error) {
	return func() (string, error) {
		b, err := os.ReadFile(path)
		return strings.TrimSpace(string(b)), err
	}
}

// signerFor wraps a key in an Agent that only signs.
func signerFor(ec *ecdsa.PrivateKey, ed ed25519.PrivateKey) *Agent {
	if ed != nil {
		return &Agent{alg: "EdDSA", ed: ed, publicJWK: map[string]interface{}{"kty": "OKP", "crv": "Ed25519", "x": b64url(ed.Public().(ed25519.PublicKey))}}
	}
	return &Agent{alg: "ES256", ec: ec, publicJWK: ecPublicJWK(&ec.PublicKey)}
}

// NewOrgAgent builds an OrgAgent; it checks the configuration, it does not call Touchque.
func NewOrgAgent(cfg OrgAgentConfig) (*OrgAgent, error) {
	id := cfg.AgentID
	if id == "" {
		id = os.Getenv("TQ_ORG_AGENT_ID")
	}
	if !orgAgentIDPattern.MatchString(id) {
		return nil, &ConfigError{Message: "set TQ_ORG_AGENT_ID (or OrgAgentConfig.AgentID): the oagt_... id from Organization → AI agents"}
	}
	issuer := cfg.Issuer
	if issuer == "" {
		issuer = os.Getenv("TQ_SSO_URL")
	}
	if issuer == "" {
		issuer = "https://sso.touchque.com"
	}
	issuer = strings.TrimRight(issuer, "/")
	u, err := url.Parse(issuer)
	if err != nil {
		return nil, &ConfigError{Message: "Issuer is not a valid URL"}
	}
	local := u.Hostname() == "localhost" || u.Hostname() == "127.0.0.1" || u.Hostname() == "::1"
	if u.Scheme != "https" && !(u.Scheme == "http" && local) {
		return nil, &ConfigError{Message: fmt.Sprintf("refusing a plaintext Issuer for %q: use https://", u.Hostname())}
	}
	a := &OrgAgent{AgentID: id, issuer: issuer, assertion: cfg.Assertion, resource: cfg.Resource, scope: cfg.Scope, tokens: map[string]orgAgentCached{}}
	if cfg.Assertion == nil {
		keyInput := cfg.PrivateKey
		if keyInput == nil {
			if env := os.Getenv("TQ_ORG_AGENT_KEY"); env != "" {
				keyInput = env
			}
		}
		if keyInput == nil {
			return nil, &ConfigError{Message: "set OrgAgentConfig.PrivateKey (or TQ_ORG_AGENT_KEY), or Assertion with the platform's token"}
		}
		ec, ed, jwkKid, err := parseAgentKey(keyInput)
		if err != nil {
			return nil, err
		}
		a.identity = signerFor(ec, ed)
		a.identity.kid = cfg.Kid
		if a.identity.kid == "" {
			a.identity.kid = jwkKid
		}
		if a.identity.kid == "" {
			a.identity.kid = JWKThumbprint(a.identity.publicJWK)
		}
	}
	dpop, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	a.dpopKey = signerFor(dpop, nil)
	timeout := cfg.TimeoutMs
	if timeout == 0 {
		timeout = 10000
	}
	a.client = &http.Client{Timeout: time.Duration(timeout) * time.Millisecond, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	return a, nil
}

// DPoPProof is a DPoP proof (RFC 9449) for one request: with the token, for a call to the app.
func (a *OrgAgent) DPoPProof(method, target, accessToken string) (string, error) {
	u, err := url.Parse(target)
	if err != nil {
		return "", err
	}
	claims := map[string]interface{}{"htm": strings.ToUpper(method), "htu": u.Scheme + "://" + u.Host + u.Path, "iat": time.Now().Unix(), "jti": randomID()}
	if accessToken != "" {
		sum := sha256.Sum256([]byte(accessToken))
		claims["ath"] = b64url(sum[:])
	}
	return a.dpopKey.sign(map[string]interface{}{"typ": "dpop+jwt", "jwk": a.dpopKey.publicJWK}, claims)
}

func (a *OrgAgent) clientAssertion(tokenURL string) (string, error) {
	if a.assertion != nil {
		return a.assertion()
	}
	now := time.Now().Unix()
	return a.identity.sign(map[string]interface{}{"typ": "JWT", "kid": a.identity.kid}, map[string]interface{}{
		"iss": a.AgentID, "sub": a.AgentID, "aud": tokenURL, "iat": now, "exp": now + 60, "jti": randomID(),
	})
}

// post sends a form to the SSO with the agent's client assertion (and, at /sso/token, a DPoP proof).
func (a *OrgAgent) post(path string, fields map[string]string, dpop bool) (map[string]interface{}, error) {
	target := a.issuer + path
	assertion, err := a.clientAssertion(a.issuer + "/sso/token")
	if err != nil {
		return nil, err
	}
	form := url.Values{"client_id": {a.AgentID}, "client_assertion_type": {AgentAssertionType}, "client_assertion": {assertion}}
	for k, v := range fields {
		if v != "" {
			form.Set(k, v)
		}
	}
	req, err := http.NewRequest("POST", target, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if dpop {
		proof, err := a.DPoPProof("POST", target, "")
		if err != nil {
			return nil, err
		}
		req.Header.Set("DPoP", proof)
	}
	resp, err := a.client.Do(req)
	if err != nil {
		return nil, &NetworkError{Message: "Touchque: network request failed: " + err.Error()}
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	data := map[string]interface{}{}
	_ = json.Unmarshal(raw, &data)
	if resp.StatusCode != 200 {
		return nil, agentErrorFrom(resp, data)
	}
	return data, nil
}

func orgAgentTokenOf(data map[string]interface{}) *OrgAgentToken {
	t := &OrgAgentToken{TokenType: "DPoP", ExpiresIn: 300}
	t.AccessToken, _ = data["access_token"].(string)
	t.Scope, _ = data["scope"].(string)
	if e, ok := data["expires_in"].(float64); ok {
		t.ExpiresIn = int(e)
	}
	if list, ok := data["authorization_details"].([]interface{}); ok {
		for _, d := range list {
			if m, ok := d.(map[string]interface{}); ok {
				t.AuthorizationDetails = append(t.AuthorizationDetails, m)
			}
		}
	}
	return t
}

// GetToken returns a token for one app (renewed 30 seconds before it expires); empty
// resource and scope fall back to the configured ones.
func (a *OrgAgent) GetToken(resource, scope string) (*OrgAgentToken, error) {
	if resource == "" {
		resource = a.resource
	}
	if scope == "" {
		scope = a.scope
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	key := resource + " " + scope
	if hit, ok := a.tokens[key]; ok && time.Until(hit.expiresAt) > 30*time.Second {
		return hit.token, nil
	}
	data, err := a.post("/sso/token", map[string]string{"grant_type": "client_credentials", "resource": resource, "scope": scope}, true)
	if err != nil {
		return nil, err
	}
	t := orgAgentTokenOf(data)
	a.tokens[key] = orgAgentCached{token: t, expiresAt: time.Now().Add(time.Duration(t.ExpiresIn) * time.Second)}
	return t, nil
}

// GetConnectionToken returns, from the token vault, a member's own access token
// at another service (Google, Microsoft 365, GitHub…) they connected on
// Touchque, for a connection that names this agent. subjectToken is the
// member's token, as for ExchangeToken; scope may only narrow what the member
// granted (empty: all of it). Touchque refreshes it; the refresh token never
// leaves. An APIError invalid_grant means the member has not connected it (or
// disconnected, or left).
func (a *OrgAgent) GetConnectionToken(subjectToken, connection, scope string) (*OrgAgentConnectionToken, error) {
	data, err := a.post("/sso/token", map[string]string{
		"grant_type": tokenExchangeGrant, "subject_token": subjectToken, "subject_token_type": accessTokenType,
		"requested_token_type": connectionTokenType, "connection": connection, "scope": scope,
	}, true)
	if err != nil {
		return nil, err
	}
	t := &OrgAgentConnectionToken{TokenType: "Bearer", Connection: connection}
	t.AccessToken, _ = data["access_token"].(string)
	t.Scope, _ = data["scope"].(string)
	if c, ok := data["connection"].(string); ok && c != "" {
		t.Connection = c
	}
	if e, ok := data["expires_in"].(float64); ok {
		t.ExpiresIn = int(e)
	}
	return t, nil
}

// ExchangeToken returns a token for a member, with their own access token for one of the
// agent's apps (RFC 8693 token exchange): sub is the member, act the agent.
func (a *OrgAgent) ExchangeToken(subjectToken, resource, scope string) (*OrgAgentToken, error) {
	if resource == "" {
		resource = a.resource
	}
	if scope == "" {
		scope = a.scope
	}
	data, err := a.post("/sso/token", map[string]string{
		"grant_type": tokenExchangeGrant, "subject_token": subjectToken, "subject_token_type": accessTokenType, "resource": resource, "scope": scope,
	}, true)
	if err != nil {
		return nil, err
	}
	return orgAgentTokenOf(data), nil
}

// AskToOpenSharedAccount asks to open a shared account (its key, from
// Organization → AI agents → Access) for a member. They open OpenURL in the
// browser where their Touchque extension is paired; their phone approves with
// this agent named and the extension signs in there. The agent never sees the
// password. message (at most 64 characters) is shown marked unverified.
func (a *OrgAgent) AskToOpenSharedAccount(account, loginHint, message string) (*SharedAccountAsk, error) {
	data, err := a.post("/sso/agents/shared-accounts/asks", map[string]string{"account": account, "login_hint": loginHint, "binding_message": message}, false)
	if err != nil {
		return nil, err
	}
	ask := &SharedAccountAsk{ExpiresIn: 600}
	ask.AskID, _ = data["ask_id"].(string)
	ask.OpenURL, _ = data["open_url"].(string)
	ask.Status, _ = data["status"].(string)
	if e, ok := data["expires_in"].(float64); ok {
		ask.ExpiresIn = int(e)
	}
	return ask, nil
}

// SharedAccountAskStatus says where an ask stands; only whether it opened,
// never anything of the account.
func (a *OrgAgent) SharedAccountAskStatus(askID string) (*SharedAccountAskStatus, error) {
	data, err := a.post("/sso/agents/shared-accounts/asks/"+url.PathEscape(askID), map[string]string{}, false)
	if err != nil {
		return nil, err
	}
	s := &SharedAccountAskStatus{}
	s.Status, _ = data["status"].(string)
	s.Reason, _ = data["reason"].(string)
	s.CaseCode, _ = data["case_code"].(string)
	return s, nil
}

// sharedAskPoll is how often WaitForSharedAccount asks.
var sharedAskPoll = 3 * time.Second

// WaitForSharedAccount polls an ask every three seconds until it ends (opened,
// refused, declined or expired) or ctx is done.
func (a *OrgAgent) WaitForSharedAccount(ctx context.Context, ask *SharedAccountAsk) (*SharedAccountAskStatus, error) {
	deadline := time.Now().Add(time.Duration(ask.ExpiresIn+5) * time.Second)
	for {
		s, err := a.SharedAccountAskStatus(ask.AskID)
		if err != nil || (s.Status != "waiting_member" && s.Status != "asked_phone") || time.Now().After(deadline) {
			return s, err
		}
		select {
		case <-ctx.Done():
			return s, ctx.Err()
		case <-time.After(sharedAskPoll):
		}
	}
}

// AskMember asks a member to approve on their phone (CIBA). Show BindingCode in the
// conversation, then WaitForMember.
func (a *OrgAgent) AskMember(p AskMemberParams) (*MemberRequest, error) {
	fields := map[string]string{"login_hint": p.LoginHint, "binding_message": p.BindingMessage, "resource": p.Resource, "scope": p.Scope}
	if fields["resource"] == "" {
		fields["resource"] = a.resource
	}
	if fields["scope"] == "" {
		fields["scope"] = a.scope
	}
	if len(p.AuthorizationDetails) > 0 {
		b, err := json.Marshal(p.AuthorizationDetails)
		if err != nil {
			return nil, err
		}
		fields["authorization_details"] = string(b)
	}
	if p.RequestedExpiry != 0 {
		fields["requested_expiry"] = fmt.Sprint(p.RequestedExpiry)
	}
	data, err := a.post("/sso/bc-authorize", fields, false)
	if err != nil {
		return nil, err
	}
	r := &MemberRequest{ExpiresIn: 300, Interval: 5}
	r.AuthReqID, _ = data["auth_req_id"].(string)
	r.BindingCode, _ = data["binding_code"].(string)
	if v, ok := data["expires_in"].(float64); ok {
		r.ExpiresIn = int(v)
	}
	if v, ok := data["interval"].(float64); ok && v >= 1 {
		r.Interval = int(v)
	}
	return r, nil
}

// WaitForMember polls for the member's answer (at the interval, slower when asked): the
// token once they approve; an *APIError access_denied or expired_token otherwise, a
// *TimeoutError after the request expired.
func (a *OrgAgent) WaitForMember(ctx context.Context, r *MemberRequest) (*OrgAgentToken, error) {
	interval := time.Duration(r.Interval) * time.Second
	deadline := time.Now().Add(time.Duration(r.ExpiresIn+5) * time.Second)
	for time.Now().Before(deadline) {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(interval):
		}
		data, err := a.post("/sso/token", map[string]string{"grant_type": cibaGrant, "auth_req_id": r.AuthReqID}, true)
		if err == nil {
			return orgAgentTokenOf(data), nil
		}
		var apiErr *APIError
		if !errors.As(err, &apiErr) {
			return nil, err
		}
		switch apiErr.Code {
		case "authorization_pending":
			continue
		case "slow_down":
			interval += 5 * time.Second
			continue
		}
		return nil, err
	}
	return nil, &TimeoutError{Message: "the member did not answer in time"}
}

// Authorize sets Authorization: DPoP <token> and a fresh DPoP proof on a request to the app.
func (a *OrgAgent) Authorize(req *http.Request, resource, scope string) error {
	t, err := a.GetToken(resource, scope)
	if err != nil {
		return err
	}
	proof, err := a.DPoPProof(req.Method, req.URL.String(), t.AccessToken)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "DPoP "+t.AccessToken)
	req.Header.Set("DPoP", proof)
	return nil
}
