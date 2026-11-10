package touchque

import (
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

// AgentsResource manages AI agents as identities of their own
// (client.Agents): register an agent with its PUBLIC key, give it an
// accountable owner and the action types it may ask approvals for, suspend,
// revoke or stop every agent at once. The agent itself never gets your API
// key: it signs in with its own key (Agent, NewAgent).
//
//	keys, _ := touchque.GenerateAgentKey("ES256")       // where the agent runs
//	agent, err := client.Agents.Create(touchque.CreateAgentParams{
//		Name: "Invoice bot", AllowedTypes: []string{"PAY_INVOICE"}, PublicKey: keys.PublicJWK,
//	})
type AgentsResource struct {
	http *httpClient
	// Vault is the token vault: people's tokens at other services, for your agents.
	Vault *AgentVaultResource

	mu       sync.Mutex
	jwks     *JWKS
	jwksAt   time.Time
	audience string
}

// RedeemedApproval is an agent's approval after RedeemApproval: what the person approved, now used.
type RedeemedApproval struct {
	ID               string `json:"id"`
	ExternalUsername string `json:"externalUsername"`
	Type             string `json:"type"`
	Agent            struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	} `json:"agent"`
	AuthorizationDetails []map[string]interface{} `json:"authorizationDetails"`
	// Details are the rows the phone showed.
	Details []struct {
		Label string `json:"label"`
		Value string `json:"value"`
	} `json:"details"`
	Presence      string `json:"presence"`
	NumberMatched bool   `json:"numberMatched"`
	DecidedAt     string `json:"decidedAt"`
	// ApprovalProof is the phone's hardware signature over the rows.
	ApprovalProof map[string]interface{} `json:"approvalProof"`
	CaseCode      string                 `json:"caseCode"`
}

// RedeemApproval uses an agent's approval exactly once, right before you
// execute: expect is checked against the token first (nothing is used on a
// mismatch), then TouchQue checks the token and marks it used, and the answer
// is checked again. Errors: *ApprovalMismatchError, or an *APIError
// (already_redeemed, token_expired, provisional…).
func (r *AgentsResource) RedeemApproval(token string, expect ApprovalExpectation) (*RedeemedApproval, error) {
	_, claims, err := DecodeApprovalToken(token)
	if err != nil {
		return nil, err
	}
	if err := AssertApprovalMatches(claims, expect); err != nil {
		return nil, err
	}
	res, err := r.http.post("/agents/approvals/redeem", map[string]interface{}{"token": token})
	if err != nil {
		return nil, err
	}
	approval := &RedeemedApproval{}
	if err := decodeInto(res["approval"], approval); err != nil {
		return nil, err
	}
	answered := map[string]interface{}{"sub": approval.ExternalUsername, "type": approval.Type, "authorization_details": normalizeJSON(approval.AuthorizationDetails)}
	if err := AssertApprovalMatches(answered, expect); err != nil {
		return nil, err
	}
	return approval, nil
}

func (r *AgentsResource) fetchJWKS(force bool) (JWKS, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if !force && r.jwks != nil && time.Since(r.jwksAt) < 5*time.Minute {
		return *r.jwks, nil
	}
	res, err := r.http.get("/agents/jwks.json")
	if err != nil {
		return JWKS{}, err
	}
	var set JWKS
	if err := decodeInto(res, &set); err != nil {
		return JWKS{}, err
	}
	r.jwks, r.jwksAt = &set, time.Now()
	return set, nil
}

// ApprovalAudience is the aud of this workspace's approval tokens
// (touchque:workspace:<id>), from GET /agents/approval-audience; asked once,
// then kept.
func (r *AgentsResource) ApprovalAudience() (string, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.audience != "" {
		return r.audience, nil
	}
	res, err := r.http.get("/agents/approval-audience")
	if err != nil {
		return "", err
	}
	var body struct {
		Audience string `json:"audience"`
	}
	if err := decodeInto(res, &body); err != nil {
		return "", err
	}
	if body.Audience == "" {
		return "", &ApprovalMismatchError{Message: "Touchque did not name this workspace's approval audience"}
	}
	r.audience = body.Audience
	return r.audience, nil
}

// VerifyApprovalToken verifies an approval token offline (TouchQue's
// published keys, expiry, aud, expect). aud must be this workspace's: an
// empty audience means ApprovalAudience, and a token without aud or for
// another workspace is refused. It does not make the token single-use:
// RedeemApproval does.
func (r *AgentsResource) VerifyApprovalToken(token, audience string, expect ApprovalExpectation) (map[string]interface{}, error) {
	if audience == "" {
		own, err := r.ApprovalAudience()
		if err != nil {
			return nil, err
		}
		audience = own
	}
	set, err := r.fetchJWKS(false)
	if err != nil {
		return nil, err
	}
	claims, err := VerifyApprovalTokenWith(token, set, audience, expect, time.Time{})
	if mismatch, ok := err.(*ApprovalMismatchError); ok && strings.Contains(mismatch.Message, "unknown key") {
		if set, err = r.fetchJWKS(true); err != nil {
			return nil, err
		}
		return VerifyApprovalTokenWith(token, set, audience, expect, time.Time{})
	}
	return claims, err
}

func newAgentsResource(http *httpClient) *AgentsResource {
	return &AgentsResource{http: http, Vault: &AgentVaultResource{http: http}}
}

// AgentVaultResource is the token vault for your agents: after your own
// OAuth flow with a person, deposit their tokens; TouchQue keeps them sealed
// and refreshes them, and the agents a connection names get a short-lived
// access token (Agent.GetConnectionToken), never the refresh token.
type AgentVaultResource struct {
	http *httpClient
}

// AgentVaultConnection is a connection: your OAuth app at another service and the agents that may use it.
type AgentVaultConnection struct {
	Name            string            `json:"name"`
	Provider        string            `json:"provider"`
	ClientID        string            `json:"clientId"`
	HasClientSecret bool              `json:"hasClientSecret"`
	Options         map[string]string `json:"options"`
	AgentIDs        []string          `json:"agentIds"`
	Connected       int               `json:"connected"`
	CreatedAt       string            `json:"createdAt"`
	UpdatedAt       string            `json:"updatedAt"`
}

// AgentVaultConnectionParams adds or replaces a connection; ClientSecret is
// kept when left empty in a replacement. Provider: google, microsoft, github,
// facebook, linkedin, x or oidc (with Issuer).
type AgentVaultConnectionParams struct {
	Provider     string   `json:"provider"`
	ClientID     string   `json:"clientId"`
	ClientSecret string   `json:"clientSecret,omitempty"`
	Tenant       string   `json:"tenant,omitempty"`
	Issuer       string   `json:"issuer,omitempty"`
	AgentIDs     []string `json:"agentIds"`
}

// AgentVaultAccount is a person's account kept in the vault (never a token).
type AgentVaultAccount struct {
	Connection       string   `json:"connection"`
	ExternalUsername string   `json:"externalUsername"`
	Scopes           []string `json:"scopes"`
	CanRefresh       bool     `json:"canRefresh"`
	LastUsedAt       *string  `json:"lastUsedAt"`
	LastAgentID      *string  `json:"lastAgentId"`
	CreatedAt        string   `json:"createdAt"`
	UpdatedAt        string   `json:"updatedAt"`
}

// AgentVaultDeposit is a person's tokens from your own OAuth flow with them.
type AgentVaultDeposit struct {
	AccessToken  string `json:"accessToken"`
	RefreshToken string `json:"refreshToken,omitempty"`
	ExpiresIn    int    `json:"expiresIn,omitempty"`
	Scope        string `json:"scope,omitempty"`
}

// ListConnections lists the vault's connections.
func (v *AgentVaultResource) ListConnections() ([]AgentVaultConnection, error) {
	res, err := v.http.get("/agents/vault/connections")
	if err != nil {
		return nil, err
	}
	var out []AgentVaultConnection
	return out, decodeInto(res["connections"], &out)
}

// PutConnection adds or replaces a connection.
func (v *AgentVaultResource) PutConnection(name string, p AgentVaultConnectionParams) (*AgentVaultConnection, error) {
	if p.AgentIDs == nil {
		p.AgentIDs = []string{}
	}
	res, err := v.http.put("/agents/vault/connections/"+url.PathEscape(name), p)
	if err != nil {
		return nil, err
	}
	out := &AgentVaultConnection{}
	return out, decodeInto(res["connection"], out)
}

// RemoveConnection removes a connection and every person's tokens kept for it.
func (v *AgentVaultResource) RemoveConnection(name string) (map[string]interface{}, error) {
	return v.http.delete("/agents/vault/connections/" + url.PathEscape(name))
}

// Deposit keeps a person's tokens (replacing earlier ones).
func (v *AgentVaultResource) Deposit(connection, user string, d AgentVaultDeposit) (*AgentVaultAccount, error) {
	res, err := v.http.put("/agents/vault/accounts/"+url.PathEscape(connection)+"/"+url.PathEscape(user), d)
	if err != nil {
		return nil, err
	}
	out := &AgentVaultAccount{}
	return out, decodeInto(res["account"], out)
}

// ListAccounts lists a person's accounts in the vault (never a token).
func (v *AgentVaultResource) ListAccounts(user string) ([]AgentVaultAccount, error) {
	res, err := v.http.getWithQuery("/agents/vault/accounts", map[string]string{"externalUsername": user})
	if err != nil {
		return nil, err
	}
	var out []AgentVaultAccount
	return out, decodeInto(res["accounts"], &out)
}

// RemoveAccount deletes a person's tokens: agents get nothing more for them there.
func (v *AgentVaultResource) RemoveAccount(connection, user string) error {
	_, err := v.http.delete("/agents/vault/accounts/" + url.PathEscape(connection) + "/" + url.PathEscape(user))
	return err
}

// AgentInfo is an agent as the partner API returns it.
type AgentInfo struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description"`
	Platform    string `json:"platform"`
	Owner       struct {
		Email  string `json:"email"`
		UserID string `json:"userId"`
	} `json:"owner"`
	// Status is active, suspended or revoked.
	Status string `json:"status"`
	// StatusReason says why it is suspended or revoked; owner_left when its
	// owner left the organization.
	StatusReason string `json:"statusReason"`
	// Blocked is what stops it right now (workspace_paused, suspended,
	// revoked, review_overdue), or "" when it may act.
	Blocked      string   `json:"blocked"`
	AllowedTypes []string `json:"allowedTypes"`
	// Policy is the policy in force (defaults filled in).
	Policy AgentPolicy `json:"policy"`
	Keys   []struct {
		Kid     string `json:"kid"`
		Kty     string `json:"kty"`
		Crv     string `json:"crv"`
		Alg     string `json:"alg"`
		AddedAt string `json:"addedAt"`
	} `json:"keys"`
	// ReviewAt: after this the agent stops until renewed (Update with ReviewInDays).
	ReviewAt   string `json:"reviewAt"`
	LastUsedAt string `json:"lastUsedAt"`
	CreatedBy  string `json:"createdBy"`
	CreatedAt  string `json:"createdAt"`
	UpdatedAt  string `json:"updatedAt"`
}

// AgentPolicy is what the agent may ask for beyond its action types; SetPolicy
// replaces it (left-out fields take the defaults).
type AgentPolicy struct {
	// RequestsPer10Min: every request of the agent (default 60).
	RequestsPer10Min int `json:"requestsPer10Min,omitempty"`
	// RequestsPerUserPer10Min: requests to one person (default 5).
	RequestsPerUserPer10Min int `json:"requestsPerUserPer10Min,omitempty"`
	// AmountPerRequest: {"TRY": "1000.00"}, the most one approval may move.
	AmountPerRequest map[string]string `json:"amountPerRequest,omitempty"`
	// AmountPerDay: over 24 hours, pending and approved requests together.
	AmountPerDay map[string]string `json:"amountPerDay,omitempty"`
	// Background: "non_critical" or "never"; critical types are never asked in the background.
	Background string `json:"background,omitempty"`
	// NewRecipients: "ask" or "deny" (a recipient this person never approved for this agent).
	NewRecipients string `json:"newRecipients,omitempty"`
	// RecipientAllowlist: IBANs / account numbers; any other is refused.
	RecipientAllowlist []string `json:"recipientAllowlist,omitempty"`
	// FourEyes: after the person, a second person approves (never the same one, never the owner).
	FourEyes *FourEyes `json:"fourEyes,omitempty"`
	// RequirePasskeyAbove: {"TRY": "10000.00"}; over it the person approves with a passkey on
	// your page (RequiresPasskey on the approval), never on the phone or with a mandate.
	RequirePasskeyAbove map[string]string `json:"requirePasskeyAbove,omitempty"`
}

// FourEyes: a second approver for listed types or amounts over Above.
type FourEyes struct {
	Approvers []string          `json:"approvers"`
	Above     map[string]string `json:"above,omitempty"`
	Types     []string          `json:"types,omitempty"`
}

// ListMandates returns an agent's mandates, only user's when not empty.
func (r *AgentsResource) ListMandates(agentID, user string) ([]Mandate, error) {
	var params map[string]string
	if user != "" {
		params = map[string]string{"externalUsername": user}
	}
	res, err := r.http.getWithQuery(agentPath(agentID)+"/mandates", params)
	if err != nil {
		return nil, err
	}
	var out []Mandate
	return out, decodeInto(res["mandates"], &out)
}

// RevokeMandate ends an agent's mandate at once.
func (r *AgentsResource) RevokeMandate(agentID, mandateID string) (*Mandate, error) {
	res, err := r.http.post(agentPath(agentID)+"/mandates/"+url.PathEscape(mandateID)+"/revoke", map[string]interface{}{})
	if err != nil {
		return nil, err
	}
	out := &Mandate{}
	return out, decodeInto(res, out)
}

// AgentBlock is a person who stopped the agent asking them.
type AgentBlock struct {
	ExternalUsername string `json:"externalUsername"`
	// Reason: not_me, coached or rejections.
	Reason     string `json:"reason"`
	ApprovalID string `json:"approvalId"`
	CreatedAt  string `json:"createdAt"`
}

// SetPolicy sets the agent's budgets, amounts, recipients and background rule.
func (r *AgentsResource) SetPolicy(agentID string, policy AgentPolicy) (*AgentInfo, error) {
	return agentFrom(r.http.put(agentPath(agentID)+"/policy", map[string]interface{}{"policy": policy}))
}

// AgentEvent is one of the workspace's agent events (AGENT_*, AGENTS_*) for a SIEM.
type AgentEvent struct {
	ID               string                 `json:"id"`
	Type             string                 `json:"type"`
	OccurredAt       string                 `json:"occurredAt"`
	Agent            *AgentEventAgent       `json:"agent"`
	ExternalUsername string                 `json:"externalUsername"`
	ApprovalID       string                 `json:"approvalId"`
	CaseCode         string                 `json:"caseCode"`
	IP               string                 `json:"ip"`
	Note             string                 `json:"note"`
	Data             map[string]interface{} `json:"data"`
}

// AgentEventAgent names the agent of an event.
type AgentEventAgent struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// AgentEventPage is a page of events, oldest first; ask again with After: Next
// (it stays the same while nothing new happened).
type AgentEventPage struct {
	Events  []AgentEvent `json:"events"`
	Next    string       `json:"next"`
	HasMore bool         `json:"hasMore"`
}

// AgentEventOptions: After (a cursor from Next), Since (ISO 8601, the first call;
// default the last 24 hours), Limit (1 to 500, default 100).
type AgentEventOptions struct {
	After string
	Since string
	Limit int
}

// ListEvents returns the workspace's agent events for a SIEM, oldest first.
func (r *AgentsResource) ListEvents(opts AgentEventOptions) (*AgentEventPage, error) {
	params := map[string]string{}
	if opts.After != "" {
		params["after"] = opts.After
	}
	if opts.Since != "" {
		params["since"] = opts.Since
	}
	if opts.Limit > 0 {
		params["limit"] = strconv.Itoa(opts.Limit)
	}
	res, err := r.http.getWithQuery("/agents/events", params)
	if err != nil {
		return nil, err
	}
	out := &AgentEventPage{}
	if err := decodeInto(res, out); err != nil {
		return nil, err
	}
	return out, nil
}

// GetWorkspacePolicy returns the workspace's policy: every agent's floor (an
// agent's own policy can only make it stricter).
func (r *AgentsResource) GetWorkspacePolicy() (*AgentPolicy, error) {
	res, err := r.http.get("/agents/workspace-policy")
	if err != nil {
		return nil, err
	}
	var out struct {
		Policy AgentPolicy `json:"policy"`
	}
	if err := decodeInto(res, &out); err != nil {
		return nil, err
	}
	return &out.Policy, nil
}

// SetWorkspacePolicy replaces the workspace's policy (a field left out sets no floor).
func (r *AgentsResource) SetWorkspacePolicy(policy AgentPolicy) (*AgentPolicy, error) {
	res, err := r.http.put("/agents/workspace-policy", map[string]interface{}{"policy": policy})
	if err != nil {
		return nil, err
	}
	var out struct {
		Policy AgentPolicy `json:"policy"`
	}
	if err := decodeInto(res, &out); err != nil {
		return nil, err
	}
	return &out.Policy, nil
}

// ListBlocks returns the people who stopped this agent asking them.
func (r *AgentsResource) ListBlocks(agentID string) ([]AgentBlock, error) {
	res, err := r.http.get(agentPath(agentID) + "/blocks")
	if err != nil {
		return nil, err
	}
	var blocks []AgentBlock
	return blocks, decodeInto(res["blocks"], &blocks)
}

// LiftBlock lets the agent ask this person again (check with them first).
func (r *AgentsResource) LiftBlock(agentID, user string) error {
	_, err := r.http.delete(agentPath(agentID) + "/blocks/" + url.PathEscape(user))
	return err
}

// AgentKillSwitch is the workspace's switch that stops every agent at once.
type AgentKillSwitch struct {
	Engaged bool   `json:"engaged"`
	Since   string `json:"since,omitempty"`
	By      string `json:"by,omitempty"`
	Reason  string `json:"reason,omitempty"`
}

// CreateAgentParams registers an agent. Set PublicKey (or PublicKeys, up to 3).
type CreateAgentParams struct {
	Name         string
	AllowedTypes []string
	PublicKey    map[string]interface{}
	PublicKeys   []map[string]interface{}
	Description  string
	// OwnerEmail: the accountable member (default: the API key's creator);
	// the agent stops when they leave the organization.
	OwnerEmail string
	Platform   string
	// ReviewInDays: 1-365, default 90.
	ReviewInDays int
}

// UpdateAgentParams changes, hands over (OwnerEmail) or renews (ReviewInDays) an agent.
type UpdateAgentParams struct {
	Name         string
	Description  *string
	OwnerEmail   string
	Platform     string
	AllowedTypes []string
	ReviewInDays int
}

// publicOnly refuses a private key before it leaves this process.
func publicOnly(jwk map[string]interface{}) (map[string]interface{}, error) {
	if _, private := jwk["d"]; private {
		return nil, &ConfigError{Message: "pass the agent's PUBLIC key: this one has private parts (d); the private key must stay where the agent runs"}
	}
	return jwk, nil
}

func agentFrom(res map[string]interface{}, err error) (*AgentInfo, error) {
	if err != nil {
		return nil, err
	}
	a := &AgentInfo{}
	if err := decodeInto(res["agent"], a); err != nil {
		return nil, err
	}
	return a, nil
}

func agentPath(agentID string) string { return "/agents/" + url.PathEscape(agentID) }

// Create registers an agent (needs the agents:write scope).
func (r *AgentsResource) Create(p CreateAgentParams) (*AgentInfo, error) {
	body := map[string]interface{}{"name": p.Name, "allowedTypes": p.AllowedTypes}
	if p.PublicKey != nil {
		k, err := publicOnly(p.PublicKey)
		if err != nil {
			return nil, err
		}
		body["publicKey"] = k
	}
	if p.PublicKeys != nil {
		keys := make([]map[string]interface{}, 0, len(p.PublicKeys))
		for _, k := range p.PublicKeys {
			clean, err := publicOnly(k)
			if err != nil {
				return nil, err
			}
			keys = append(keys, clean)
		}
		body["publicKeys"] = keys
	}
	if p.Description != "" {
		body["description"] = p.Description
	}
	if p.OwnerEmail != "" {
		body["ownerEmail"] = p.OwnerEmail
	}
	if p.Platform != "" {
		body["platform"] = p.Platform
	}
	if p.ReviewInDays != 0 {
		body["reviewInDays"] = p.ReviewInDays
	}
	return agentFrom(r.http.post("/agents", body))
}

// List returns the workspace's agents (only those in status, when given) and its kill switch.
func (r *AgentsResource) List(status string) ([]AgentInfo, *AgentKillSwitch, error) {
	var params map[string]string
	if status != "" {
		params = map[string]string{"status": status}
	}
	res, err := r.http.getWithQuery("/agents", params)
	if err != nil {
		return nil, nil, err
	}
	var agents []AgentInfo
	if err := decodeInto(res["agents"], &agents); err != nil {
		return nil, nil, err
	}
	ks := &AgentKillSwitch{}
	if err := decodeInto(res["killSwitch"], ks); err != nil {
		return nil, nil, err
	}
	return agents, ks, nil
}

// Get returns one agent.
func (r *AgentsResource) Get(agentID string) (*AgentInfo, error) {
	return agentFrom(r.http.get(agentPath(agentID)))
}

// Update changes, hands over or renews an agent.
func (r *AgentsResource) Update(agentID string, p UpdateAgentParams) (*AgentInfo, error) {
	body := map[string]interface{}{}
	if p.Name != "" {
		body["name"] = p.Name
	}
	if p.Description != nil {
		body["description"] = *p.Description
	}
	if p.OwnerEmail != "" {
		body["ownerEmail"] = p.OwnerEmail
	}
	if p.Platform != "" {
		body["platform"] = p.Platform
	}
	if p.AllowedTypes != nil {
		body["allowedTypes"] = p.AllowedTypes
	}
	if p.ReviewInDays != 0 {
		body["reviewInDays"] = p.ReviewInDays
	}
	return agentFrom(r.http.patch(agentPath(agentID), body))
}

// AddKey adds a key (rotation: add the new one, move the agent to it, then remove the old one).
func (r *AgentsResource) AddKey(agentID string, publicKey map[string]interface{}) (*AgentInfo, error) {
	k, err := publicOnly(publicKey)
	if err != nil {
		return nil, err
	}
	return agentFrom(r.http.post(agentPath(agentID)+"/keys", map[string]interface{}{"publicKey": k}))
}

// RemoveKey removes a key; tokens the agent got with it stop at once.
func (r *AgentsResource) RemoveKey(agentID, kid string) (*AgentInfo, error) {
	return agentFrom(r.http.delete(agentPath(agentID) + "/keys/" + url.PathEscape(kid)))
}

// Suspend stops an agent at once (its tokens too) until resumed.
func (r *AgentsResource) Suspend(agentID, reason string) (*AgentInfo, error) {
	body := map[string]interface{}{}
	if reason != "" {
		body["reason"] = reason
	}
	return agentFrom(r.http.post(agentPath(agentID)+"/suspend", body))
}

// Resume lets a suspended agent act again.
func (r *AgentsResource) Resume(agentID string) (*AgentInfo, error) {
	return agentFrom(r.http.post(agentPath(agentID)+"/resume", map[string]interface{}{}))
}

// Revoke revokes an agent for good (the record stays for the audit trail).
func (r *AgentsResource) Revoke(agentID string) (*AgentInfo, error) {
	return agentFrom(r.http.delete(agentPath(agentID)))
}

// SetKillSwitch stops (true) or restarts (false) every agent of the workspace at once.
func (r *AgentsResource) SetKillSwitch(engaged bool, reason string) (*AgentKillSwitch, error) {
	body := map[string]interface{}{"engaged": engaged}
	if reason != "" {
		body["reason"] = reason
	}
	res, err := r.http.put("/agents/kill-switch", body)
	if err != nil {
		return nil, err
	}
	ks := &AgentKillSwitch{}
	if err := decodeInto(res["killSwitch"], ks); err != nil {
		return nil, err
	}
	return ks, nil
}
