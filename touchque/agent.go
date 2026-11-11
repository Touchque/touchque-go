package touchque

// The agent side: an AI agent calls Touchque with its OWN key, never with
// your API key. Agent signs a private_key_jwt assertion (RFC 7523) for a
// 10-minute token bound to its key with DPoP (RFC 9449), and proves the key
// on every call, so a stolen token is useless on its own.
//
//	agent, err := touchque.NewAgent(touchque.AgentConfig{})   // TQ_AGENT_ID, TQ_AGENT_KEY (JWK JSON or PEM)
//	me, err := agent.Me()

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
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

// AgentAssertionType is the client_assertion_type of an agent's token request.
const AgentAssertionType = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"

var agentIDPattern = regexp.MustCompile(`^agt_[a-z2-9]{20}$`)

func b64url(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

// JWKThumbprint is the RFC 7638 thumbprint of a P-256 or Ed25519 public key (the default kid).
func JWKThumbprint(jwk map[string]interface{}) string {
	var members string
	if jwk["kty"] == "EC" {
		members = fmt.Sprintf(`{"crv":%q,"kty":"EC","x":%q,"y":%q}`, jwk["crv"], jwk["x"], jwk["y"])
	} else {
		members = fmt.Sprintf(`{"crv":%q,"kty":%q,"x":%q}`, jwk["crv"], jwk["kty"], jwk["x"])
	}
	sum := sha256.Sum256([]byte(members))
	return b64url(sum[:])
}

// AgentKeyPair is a new agent key: register PublicJWK, keep PrivateJWK where the agent runs.
type AgentKeyPair struct {
	PrivateJWK map[string]interface{}
	PublicJWK  map[string]interface{}
}

// GenerateAgentKey makes a new key pair for an agent: "ES256" (P-256,
// default when empty) or "EdDSA" (Ed25519); kid = the RFC 7638 thumbprint.
func GenerateAgentKey(alg string) (*AgentKeyPair, error) {
	var public map[string]interface{}
	var d []byte
	switch alg {
	case "", "ES256":
		alg = "ES256"
		priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, err
		}
		if d, err = priv.Bytes(); err != nil {
			return nil, err
		}
		public = ecPublicJWK(&priv.PublicKey)
	case "EdDSA":
		pub, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return nil, err
		}
		d = priv.Seed()
		public = map[string]interface{}{"kty": "OKP", "crv": "Ed25519", "x": b64url(pub)}
	default:
		return nil, &ConfigError{Message: "alg must be ES256 or EdDSA"}
	}
	kid := JWKThumbprint(public)
	private := map[string]interface{}{}
	pubOut := map[string]interface{}{}
	for k, v := range public {
		private[k] = v
		pubOut[k] = v
	}
	private["d"], private["kid"], private["alg"] = b64url(d), kid, alg
	pubOut["kid"], pubOut["alg"] = kid, alg
	return &AgentKeyPair{PrivateJWK: private, PublicJWK: pubOut}, nil
}

func ecPublicJWK(pub *ecdsa.PublicKey) map[string]interface{} {
	raw, _ := pub.Bytes() // 0x04 || X || Y
	return map[string]interface{}{"kty": "EC", "crv": "P-256", "x": b64url(raw[1:33]), "y": b64url(raw[33:65])}
}

// AgentConfig configures an Agent. Empty fields fall back to the environment:
// TQ_AGENT_ID, TQ_AGENT_KEY (a JWK as JSON, or a PEM), TQ_API_URL.
type AgentConfig struct {
	AgentID string
	// PrivateKey: a JWK (map or JSON string), a PEM string, or an
	// *ecdsa.PrivateKey / ed25519.PrivateKey.
	PrivateKey interface{}
	// Kid it was registered with; default: the JWK's kid, else its RFC 7638 thumbprint.
	Kid     string
	BaseURL string
	// Scope: space-separated subset of "agent:read approvals:request approvals:read vault:read"; default all.
	Scope     string
	TimeoutMs int
}

// Agent is an AI agent's own Touchque client.
type Agent struct {
	AgentID   string
	alg       string
	ec        *ecdsa.PrivateKey
	ed        ed25519.PrivateKey
	publicJWK map[string]interface{}
	kid       string
	baseURL   string
	scope     string
	client    *http.Client

	mu        sync.Mutex
	token     string
	expiresAt time.Time
}

func parseAgentKey(value interface{}) (*ecdsa.PrivateKey, ed25519.PrivateKey, string, error) {
	bad := &ConfigError{Message: "PrivateKey must be the agent's private key: a JWK (map or JSON), a PEM string or a Go private key"}
	if s, ok := value.(string); ok && strings.HasPrefix(strings.TrimSpace(s), "{") {
		var m map[string]interface{}
		if err := json.Unmarshal([]byte(s), &m); err != nil {
			return nil, nil, "", bad
		}
		value = m
	}
	switch v := value.(type) {
	case map[string]interface{}:
		ds, _ := v["d"].(string)
		d, err := base64.RawURLEncoding.DecodeString(ds)
		if err != nil || len(d) == 0 {
			return nil, nil, "", bad
		}
		kid, _ := v["kid"].(string)
		switch {
		case v["kty"] == "OKP" && v["crv"] == "Ed25519" && len(d) == ed25519.SeedSize:
			return nil, ed25519.NewKeyFromSeed(d), kid, nil
		case v["kty"] == "EC" && v["crv"] == "P-256":
			priv, err := ecdsa.ParseRawPrivateKey(elliptic.P256(), d)
			if err != nil {
				return nil, nil, "", bad
			}
			return priv, nil, kid, nil
		}
		return nil, nil, "", &ConfigError{Message: "the agent key must be EC P-256 or Ed25519"}
	case string:
		block, _ := pem.Decode([]byte(v))
		if block == nil {
			return nil, nil, "", bad
		}
		if key, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
			return parseAgentKey(key)
		}
		if key, err := x509.ParseECPrivateKey(block.Bytes); err == nil {
			return parseAgentKey(key)
		}
		return nil, nil, "", bad
	case *ecdsa.PrivateKey:
		if v.Curve != elliptic.P256() {
			return nil, nil, "", &ConfigError{Message: "an EC agent key must be on P-256"}
		}
		return v, nil, "", nil
	case ed25519.PrivateKey:
		return nil, v, "", nil
	}
	return nil, nil, "", bad
}

// NewAgent builds an Agent; it checks the configuration, it does not call Touchque.
func NewAgent(cfg AgentConfig) (*Agent, error) {
	id := cfg.AgentID
	if id == "" {
		id = os.Getenv("TQ_AGENT_ID")
	}
	if !agentIDPattern.MatchString(id) {
		return nil, &ConfigError{Message: "set TQ_AGENT_ID (or AgentConfig.AgentID): the agt_... id from client.Agents.Create"}
	}
	keyInput := cfg.PrivateKey
	if keyInput == nil {
		if env := os.Getenv("TQ_AGENT_KEY"); env != "" {
			keyInput = env
		}
	}
	if keyInput == nil {
		return nil, &ConfigError{Message: "set TQ_AGENT_KEY (or AgentConfig.PrivateKey): the agent's private key"}
	}
	ec, ed, jwkKid, err := parseAgentKey(keyInput)
	if err != nil {
		return nil, err
	}
	a := &Agent{AgentID: id, ec: ec, ed: ed, scope: cfg.Scope}
	if ed != nil {
		a.alg = "EdDSA"
		a.publicJWK = map[string]interface{}{"kty": "OKP", "crv": "Ed25519", "x": b64url(ed.Public().(ed25519.PublicKey))}
	} else {
		a.alg = "ES256"
		a.publicJWK = ecPublicJWK(&ec.PublicKey)
	}
	a.kid = cfg.Kid
	if a.kid == "" {
		a.kid = jwkKid
	}
	if a.kid == "" {
		a.kid = JWKThumbprint(a.publicJWK)
	}
	base := cfg.BaseURL
	if base == "" {
		base = os.Getenv("TQ_API_URL")
	}
	if base == "" {
		base = "https://api.touchque.com"
	}
	a.baseURL = strings.TrimRight(base, "/")
	u, err := url.Parse(a.baseURL)
	if err != nil {
		return nil, &ConfigError{Message: "BaseURL is not a valid URL"}
	}
	local := u.Hostname() == "localhost" || u.Hostname() == "127.0.0.1" || u.Hostname() == "::1"
	if u.Scheme != "https" && !(u.Scheme == "http" && local) {
		return nil, &ConfigError{Message: fmt.Sprintf("refusing a plaintext BaseURL for %q: use https://", u.Hostname())}
	}
	timeout := cfg.TimeoutMs
	if timeout == 0 {
		timeout = 10000
	}
	a.client = &http.Client{
		Timeout:       time.Duration(timeout) * time.Millisecond,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	return a, nil
}

func (a *Agent) sign(header, payload map[string]interface{}) (string, error) {
	header["alg"] = a.alg
	h, err := json.Marshal(header)
	if err != nil {
		return "", err
	}
	p, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}
	input := b64url(h) + "." + b64url(p)
	var sig []byte
	if a.alg == "EdDSA" {
		sig = ed25519.Sign(a.ed, []byte(input))
	} else {
		digest := sha256.Sum256([]byte(input))
		r, s, err := ecdsa.Sign(rand.Reader, a.ec, digest[:])
		if err != nil {
			return "", err
		}
		sig = make([]byte, 64)
		r.FillBytes(sig[:32])
		s.FillBytes(sig[32:])
	}
	return input + "." + b64url(sig), nil
}

func randomID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return b64url(b)
}

func (a *Agent) dpop(method, target, accessToken string) (string, error) {
	claims := map[string]interface{}{"htm": method, "htu": target, "iat": time.Now().Unix(), "jti": randomID()}
	if accessToken != "" {
		sum := sha256.Sum256([]byte(accessToken))
		claims["ath"] = b64url(sum[:])
	}
	return a.sign(map[string]interface{}{"typ": "dpop+jwt", "jwk": a.publicJWK}, claims)
}

func agentErrorFrom(resp *http.Response, data map[string]interface{}) *APIError {
	if _, ok := data["code"]; !ok {
		if e, ok := data["error"].(string); ok {
			data["code"] = e
		}
	}
	apiErr := apiErrorFrom(resp, data)
	if d, ok := data["error_description"].(string); ok && d != "" {
		apiErr.Message = d
	}
	if ra, ok := data["retry_after"].(float64); ok {
		apiErr.RetryAfter = int(ra)
	}
	return apiErr
}

func (a *Agent) do(req *http.Request) (*http.Response, map[string]interface{}, error) {
	resp, err := a.client.Do(req)
	if err != nil {
		return nil, nil, &NetworkError{Message: "Touchque: network request failed: " + err.Error()}
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 10<<20))
	data := map[string]interface{}{}
	_ = json.Unmarshal(raw, &data)
	return resp, data, nil
}

func (a *Agent) fetchToken() (string, error) {
	target := a.baseURL + "/agents/token"
	now := time.Now().Unix()
	assertion, err := a.sign(map[string]interface{}{"typ": "JWT", "kid": a.kid}, map[string]interface{}{
		"iss": a.AgentID, "sub": a.AgentID, "aud": target, "iat": now, "exp": now + 60, "jti": randomID(),
	})
	if err != nil {
		return "", err
	}
	form := url.Values{"grant_type": {"client_credentials"}, "client_assertion_type": {AgentAssertionType}, "client_assertion": {assertion}}
	if a.scope != "" {
		form.Set("scope", a.scope)
	}
	proof, err := a.dpop("POST", target, "")
	if err != nil {
		return "", err
	}
	req, err := http.NewRequest("POST", target, strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("DPoP", proof)
	resp, data, err := a.do(req)
	if err != nil {
		return "", err
	}
	if resp.StatusCode != 200 {
		return "", agentErrorFrom(resp, data)
	}
	token, _ := data["access_token"].(string)
	expiresIn, _ := data["expires_in"].(float64)
	if expiresIn == 0 {
		expiresIn = 600
	}
	a.token, a.expiresAt = token, time.Now().Add(time.Duration(expiresIn)*time.Second)
	return token, nil
}

// AccessToken returns the agent's current token, renewed a minute before it expires.
func (a *Agent) AccessToken() (string, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.token != "" && time.Until(a.expiresAt) > time.Minute {
		return a.token, nil
	}
	return a.fetchToken()
}

// request makes a call with the agent's token and a fresh DPoP proof; one
// retry with a new token when Touchque no longer knows it.
func (a *Agent) request(method, path string, body interface{}, retried bool) (map[string]interface{}, error) {
	token, err := a.AccessToken()
	if err != nil {
		return nil, err
	}
	target := a.baseURL + path
	proof, err := a.dpop(method, strings.SplitN(target, "?", 2)[0], token)
	if err != nil {
		return nil, err
	}
	var reader io.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			return nil, err
		}
		reader = bytes.NewReader(raw)
	}
	req, err := http.NewRequest(method, target, reader)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "DPoP "+token)
	req.Header.Set("DPoP", proof)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, data, err := a.do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode == 401 && !retried && data["code"] == "invalid_token" {
		a.mu.Lock()
		a.token = ""
		a.mu.Unlock()
		return a.request(method, path, body, true)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, agentErrorFrom(resp, data)
	}
	return data, nil
}

// AgentSelf is the agent as Touchque sees it.
type AgentSelf struct {
	Agent struct {
		ID           string   `json:"id"`
		Name         string   `json:"name"`
		Platform     string   `json:"platform"`
		AllowedTypes []string `json:"allowedTypes"`
		ReviewAt     string   `json:"reviewAt"`
		Owner        struct {
			Email string `json:"email"`
		} `json:"owner"`
	} `json:"agent"`
	Workspace struct {
		CompanyName string `json:"companyName"`
	} `json:"workspace"`
	Scope string `json:"scope"`
}

// AgentApprovalParams asks a person to approve on their Touchque phone.
type AgentApprovalParams struct {
	// User is the person the agent acts for (their phone approves).
	User string
	// Type is one of the agent's allowed action types.
	Type string
	// AuthorizationDetails is what exactly to approve; Touchque draws the phone's rows from it.
	AuthorizationDetails []map[string]interface{}
	// Reason is the agent's own words, shown on the phone as unverified.
	Reason string
	// Presence: "interactive" (default; a person reads the number in your
	// conversation) or "background" (no number, never for critical types).
	Presence string
	// ExpiresIn: seconds the phone may approve it, 60-3600 (default 300).
	ExpiresIn   int
	Locale      string
	ReferenceID string
	ClientIP    string
	UserAgent   string
	// MandateID approves within this active mandate: no push (see RequestMandate).
	MandateID string
}

// MandateParams asks a person for a mandate: one approval on the phone for a bounded series of requests.
type MandateParams struct {
	User     string
	Type     string
	MaxCount int
	// MaxTotal: {"currency": "TRY", "amount": "1000"}.
	MaxTotal   map[string]string
	PerRequest string
	// Recipients: IBANs / account numbers it may pay; none = any.
	Recipients []string
	// ValidFor: seconds it lasts (300-604800, default 86400).
	ValidFor  int
	Reason    string
	ExpiresIn int
	Locale    string
}

// Mandate is a mandate's state and what is left.
type Mandate struct {
	MandateID string `json:"mandateId"`
	// Status: pending, active, rejected, expired, provisional, revoked, exhausted.
	Status           string            `json:"status"`
	ExternalUsername string            `json:"externalUsername"`
	Type             string            `json:"type"`
	MaxCount         int               `json:"maxCount"`
	UsedCount        int               `json:"usedCount"`
	MaxTotal         map[string]string `json:"maxTotal"`
	Used             map[string]string `json:"used"`
	PerRequest       map[string]string `json:"perRequest"`
	Recipients       []string          `json:"recipients"`
	ValidUntil       string            `json:"validUntil"`
	ChallengeCode    string            `json:"challengeCode"`
	RevokedAt        string            `json:"revokedAt"`
}

// AgentApprovalState is where an approval request is.
type AgentApprovalState struct {
	ApprovalID string `json:"approvalId"`
	// Status: pending, approved, rejected, blocked, expired, provisional, revoked, stale, redeemed.
	Status   string `json:"status"`
	Presence string `json:"presence"`
	// ChallengeCode: while pending and interactive, show it in the conversation.
	ChallengeCode string `json:"challengeCode"`
	// RequiresPasskey: over the policy's RequirePasskeyAbove the person approves with a
	// passkey on your page (<touchque-approval request-id="ApprovalID">), not on the phone.
	RequiresPasskey bool   `json:"requiresPasskey"`
	ExpiresAt       string `json:"expiresAt"`
	CaseCode        string `json:"caseCode"`
	Reason          string `json:"reason"`
	// ApprovalToken, once approved: hand it to the service that executes (it redeems it once).
	ApprovalToken  string `json:"approvalToken"`
	TokenExpiresIn int    `json:"tokenExpiresIn"`
	// Four eyes: who approves second, and the number they type when their action type needs one.
	SecondApprover      string `json:"secondApprover"`
	SecondChallengeCode string `json:"secondChallengeCode"`
	// MandateID and Mandate: approved within this mandate (no push).
	MandateID string   `json:"mandateId"`
	Mandate   *Mandate `json:"mandate"`
}

// RequestApproval asks the person to approve on their Touchque phone. Show
// ChallengeCode in your conversation (interactive): the person types it on the phone.
func (a *Agent) RequestApproval(p AgentApprovalParams) (*AgentApprovalState, error) {
	body := map[string]interface{}{"externalUsername": p.User, "type": p.Type, "authorizationDetails": p.AuthorizationDetails}
	for key, value := range map[string]string{"reason": p.Reason, "presence": p.Presence, "locale": p.Locale, "referenceId": p.ReferenceID, "clientIp": p.ClientIP, "userAgent": p.UserAgent, "mandateId": p.MandateID} {
		if value != "" {
			body[key] = value
		}
	}
	if p.ExpiresIn != 0 {
		body["expiresIn"] = p.ExpiresIn
	}
	res, err := a.request("POST", "/agents/approvals", body, false)
	if err != nil {
		return nil, err
	}
	out := &AgentApprovalState{}
	return out, decodeInto(res, out)
}

// RequestMandate asks the person for a mandate. Show ChallengeCode; once
// active, pass MandateID to RequestApproval and each request within it is
// approved without a push.
func (a *Agent) RequestMandate(p MandateParams) (*Mandate, error) {
	body := map[string]interface{}{"externalUsername": p.User, "type": p.Type, "maxCount": p.MaxCount, "maxTotal": p.MaxTotal}
	for key, value := range map[string]string{"perRequest": p.PerRequest, "reason": p.Reason, "locale": p.Locale} {
		if value != "" {
			body[key] = value
		}
	}
	if len(p.Recipients) > 0 {
		body["recipients"] = p.Recipients
	}
	if p.ValidFor != 0 {
		body["validFor"] = p.ValidFor
	}
	if p.ExpiresIn != 0 {
		body["expiresIn"] = p.ExpiresIn
	}
	res, err := a.request("POST", "/agents/mandates", body, false)
	if err != nil {
		return nil, err
	}
	out := &Mandate{}
	return out, decodeInto(res, out)
}

// AgentConnectionToken is a person's own access token at another service (the token vault).
type AgentConnectionToken struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	// ExpiresIn is 0 when the service does not say.
	ExpiresIn  int    `json:"expires_in"`
	Scope      string `json:"scope"`
	Connection string `json:"connection"`
}

// GetConnectionToken returns, from the token vault, a person's own access
// token at another service for a connection that names this agent
// (AgentsResource.Vault). Touchque refreshes it; the refresh token never
// leaves. scope may only narrow what the person granted (empty: all of it).
func (a *Agent) GetConnectionToken(user, connection, scope string) (*AgentConnectionToken, error) {
	body := map[string]interface{}{"externalUsername": user, "connection": connection}
	if scope != "" {
		body["scope"] = scope
	}
	res, err := a.request("POST", "/agents/vault/token", body, false)
	if err != nil {
		return nil, err
	}
	out := &AgentConnectionToken{}
	return out, decodeInto(res, out)
}

// GetMandate returns a mandate's state and what is left.
func (a *Agent) GetMandate(mandateID string) (*Mandate, error) {
	res, err := a.request("GET", "/agents/mandates/"+url.PathEscape(mandateID), nil, false)
	if err != nil {
		return nil, err
	}
	out := &Mandate{}
	return out, decodeInto(res, out)
}

// RevokeMandate gives up a mandate.
func (a *Agent) RevokeMandate(mandateID string) (*Mandate, error) {
	res, err := a.request("POST", "/agents/mandates/"+url.PathEscape(mandateID)+"/revoke", map[string]interface{}{}, false)
	if err != nil {
		return nil, err
	}
	out := &Mandate{}
	return out, decodeInto(res, out)
}

// GetApproval returns where an approval request is; ApprovalToken once approved.
func (a *Agent) GetApproval(approvalID string) (*AgentApprovalState, error) {
	res, err := a.request("GET", "/agents/approvals/"+url.PathEscape(approvalID), nil, false)
	if err != nil {
		return nil, err
	}
	out := &AgentApprovalState{}
	return out, decodeInto(res, out)
}

// WaitForApproval polls until the person approves (the state holds
// ApprovalToken). It returns an *ApprovalError when the request ends
// otherwise and a *TimeoutError after timeout (0: 10 minutes). An approval
// given during a phone call stays provisional until the phone confirms it, and
// four eyes stay awaiting_second until the second person answers.
// RequireApproval asks the person's phone and waits for the answer: the
// approved state (holding ApprovalToken), an *ApprovalError when it ended
// otherwise, or a timeout. onChallenge (may be nil) gets the state while the
// phone waits: show its ChallengeCode in the conversation. Put it in front of
// any tool call an agent framework makes (LangChain, LlamaIndex, Eino, a
// custom loop) so the call runs only after the person approved.
func (a *Agent) RequireApproval(ctx context.Context, p AgentApprovalParams, onChallenge func(*AgentApprovalState), timeout time.Duration) (*AgentApprovalState, error) {
	asked, err := a.RequestApproval(p)
	if err != nil {
		return nil, err
	}
	if asked.Status == "approved" && asked.ApprovalToken != "" {
		return asked, nil
	}
	if asked.ChallengeCode != "" && onChallenge != nil {
		onChallenge(asked)
	}
	if timeout == 0 {
		timeout = 5 * time.Minute
	}
	return a.WaitForApproval(ctx, asked.ApprovalID, timeout, 0)
}

func (a *Agent) WaitForApproval(ctx context.Context, approvalID string, timeout, interval time.Duration) (*AgentApprovalState, error) {
	if timeout == 0 {
		timeout = 10 * time.Minute
	}
	if interval < 500*time.Millisecond {
		interval = 500 * time.Millisecond
	}
	end := time.Now().Add(timeout)
	for {
		state, err := a.GetApproval(approvalID)
		if err != nil {
			return nil, err
		}
		switch state.Status {
		case "approved":
			if state.ApprovalToken != "" {
				return state, nil
			}
		case "rejected", "blocked", "revoked", "expired", "stale", "redeemed":
			return nil, &ApprovalError{ApprovalID: approvalID, Status: state.Status, Reason: state.Reason}
		}
		if time.Now().Add(interval).After(end) {
			return nil, &TimeoutError{Message: fmt.Sprintf("Touchque: approval %q was not approved within %s", approvalID, timeout)}
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(interval):
		}
	}
}

// Me returns the agent as Touchque sees it: its action types, owner, review date and workspace.
func (a *Agent) Me() (*AgentSelf, error) {
	res, err := a.request("GET", "/agents/me", nil, false)
	if err != nil {
		return nil, err
	}
	out := &AgentSelf{}
	if err := decodeInto(res, out); err != nil {
		return nil, err
	}
	return out, nil
}
