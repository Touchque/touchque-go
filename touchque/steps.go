package touchque

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"strings"
	"time"
)

// StepState is the state a headless approval is in.
type StepState string

const (
	StepWaiting         StepState = "waiting" // push sent — show Number (if any) and wait
	StepApproved        StepState = "approved"
	StepRejected        StepState = "rejected"
	StepExpired         StepState = "expired"
	StepEnroll          StepState = "enroll"           // no phone linked yet — show Enroll.QRCodeDataURL
	StepPasskeyRequired StepState = "passkey_required" // policy: approve with a passkey (browser ceremony)
	StepOffline         StepState = "offline"          // offline approval started — show Offline.QRDataURL, ask for the code
	StepBlocked         StepState = "blocked"          // refused by policy / risk / action disabled — see Reason
	StepFrozen          StepState = "frozen"           // too many rejections — see RetryAfter
	StepRateLimited     StepState = "rate_limited"     // too many requests — see RetryAfter
)

// Step is what a headless approval currently looks like — safe to
// json.Marshal and send to the browser. It never contains API secrets.
type Step struct {
	State      StepState     `json:"state"`
	RequestID  string        `json:"requestId,omitempty"`
	Number     string        `json:"number,omitempty"`
	ExpiresAt  string        `json:"expiresAt,omitempty"`
	Details    []LoginDetail `json:"details,omitempty"`
	Enroll     *EnrollStep   `json:"enroll,omitempty"`
	Offline    *OfflineStep  `json:"offline,omitempty"`
	Reason     string        `json:"reason,omitempty"`
	RetryAfter int           `json:"retryAfter,omitempty"`
	Assurance  *Assurance    `json:"assurance,omitempty"`
}

// EnrollStep is shown when the user has not linked a phone yet.
type EnrollStep struct {
	QRCodeDataURL string   `json:"qrCodeDataUrl,omitempty"`
	RecoveryCodes []string `json:"recoveryCodes,omitempty"`
	ExpiresAt     string   `json:"expiresAt,omitempty"`
}

// OfflineStep is shown while the user types the code from an offline challenge.
type OfflineStep struct {
	ChallengeID   string `json:"challengeId,omitempty"`
	QRDataURL     string `json:"qrDataUrl,omitempty"`
	ExpiresAt     string `json:"expiresAt,omitempty"`
	TotpAvailable bool   `json:"totpAvailable,omitempty"`
	AttemptsLeft  int    `json:"attemptsLeft,omitempty"`
}

// Approval is a request that was approved and consumed exactly once.
type Approval struct {
	RequestID     string      `json:"requestId"`
	User          string      `json:"user"`
	Action        string      `json:"action"`
	Assurance     *Assurance  `json:"assurance,omitempty"`
	ConfirmedVia  string      `json:"confirmedVia,omitempty"`
	ApprovalProof interface{} `json:"approvalProof,omitempty"`
}

// StartOptions configures Start.
type StartOptions struct {
	// Details: shown on the phone and bound to the approval. Build it from server-side state.
	Details []LoginDetail
	// ReferenceID: your own transaction id, bound to the approval.
	ReferenceID string
	// IP / UserAgent: the end user's — shown on the phone.
	IP        string
	UserAgent string
	// NoEnroll: set true to get StepEnroll{} (no QR) instead of issuing one,
	// when the user has no linked phone.
	NoEnroll bool
}

// normalizeDetails matches the API's own normalization: nil in, nil out.
func normalizeDetails(details []LoginDetail) []LoginDetail {
	if len(details) == 0 {
		return nil
	}
	out := make([]LoginDetail, len(details))
	for i, d := range details {
		out[i] = LoginDetail{Label: strings.TrimSpace(d.Label), Value: strings.TrimSpace(d.Value)}
	}
	return out
}

func detailsDigest(details []LoginDetail) string {
	norm := normalizeDetails(details)
	if len(norm) == 0 {
		return ""
	}
	parts := make([]string, len(norm))
	for i, d := range norm {
		parts[i] = d.Label + "\x1f" + d.Value
	}
	sum := sha256.Sum256([]byte(strings.Join(parts, "\x1e")))
	return hex.EncodeToString(sum[:])
}

// Start starts an approval for action — never waits.
func (c *Client) Start(action, user string, opts StartOptions) (*Step, error) {
	if user == "" {
		return nil, &ConfigError{Message: "touchque: Start() needs the user id"}
	}
	norm := normalizeDetails(opts.Details)
	res, err := c.Login.RequestWithOptions(LoginRequestOptions{
		ExternalUsername: user, Type: action, ReferenceID: opts.ReferenceID,
		ClientIP: opts.IP, UserAgent: opts.UserAgent, Details: norm,
	})
	if err == nil {
		if res.RequiresPasskey {
			return &Step{State: StepPasskeyRequired, RequestID: res.RequestID, ExpiresAt: res.ExpiresAt, Details: norm}, nil
		}
		return &Step{State: StepWaiting, RequestID: res.RequestID, Number: res.ChallengeCode, ExpiresAt: res.ExpiresAt, Details: norm}, nil
	}

	apiErr, ok := err.(*APIError)
	if !ok {
		return nil, err
	}
	switch {
	case apiErr.StatusCode == 404 && (apiErr.Code == "device_not_linked" || strings.Contains(strings.ToLower(apiErr.Message), "linked device")):
		if opts.NoEnroll {
			return &Step{State: StepEnroll}, nil
		}
		return enrollStep(c, user)
	case apiErr.StatusCode == 423:
		return &Step{State: StepFrozen, RetryAfter: apiErr.RetryAfter}, nil
	case apiErr.StatusCode == 429:
		return &Step{State: StepRateLimited, RetryAfter: apiErr.RetryAfter}, nil
	case apiErr.StatusCode == 400 && (apiErr.Code == "unknown_action" || strings.Contains(strings.ToLower(apiErr.Message), "invalid action type")):
		return nil, &ConfigError{Message: "touchque: unknown action \"" + action + "\". Create it once with client.Actions.Define(\"" + action + "\", ...) or in the Dashboard (Action Types)."}
	case apiErr.StatusCode == 403:
		reason := apiErr.Reason
		if reason == "" && (apiErr.Code == "passkey_not_registered" || dataError(apiErr) == "phishing_resistant_required") {
			reason = "passkey_not_registered"
		}
		if reason == "" && apiErr.Code == "action_disabled" {
			reason = "action_disabled"
		}
		if reason == "" {
			reason = apiErr.Code
		}
		if reason == "" {
			reason = "blocked"
		}
		return &Step{State: StepBlocked, Reason: reason}, nil
	}
	return nil, err
}

func dataError(err *APIError) string {
	if err.Data == nil {
		return ""
	}
	if v, ok := err.Data["error"].(string); ok {
		return v
	}
	return ""
}

// enrollStep issues a first-time-linking QR. Never unlinks a phone: a secret
// is only re-issued when the account is confirmed NOT linked.
func enrollStep(c *Client, user string) (*Step, error) {
	gen, err := c.Auth.GenerateSecret(user)
	if err == nil {
		return &Step{State: StepEnroll, Enroll: &EnrollStep{QRCodeDataURL: gen.QRCodeDataURL, RecoveryCodes: gen.RecoveryCodes, ExpiresAt: gen.ExpiresAt}}, nil
	}
	apiErr, ok := err.(*APIError)
	if !ok || apiErr.StatusCode != 409 {
		return nil, err
	}
	current, cerr := c.Auth.GetUser(user)
	if cerr == nil && (current.Used || current.DeviceID != "") {
		return &Step{State: StepEnroll, Reason: "already_linked"}, nil
	}
	reset, err := c.Auth.ResetSecret(user)
	if err != nil {
		return nil, err
	}
	return &Step{State: StepEnroll, Enroll: &EnrollStep{QRCodeDataURL: reset.QRCodeDataURL, RecoveryCodes: reset.RecoveryCodes, ExpiresAt: reset.ExpiresAt}}, nil
}

var stepStateMap = map[string]StepState{
	"PENDING": StepWaiting, "CONFIRMED": StepApproved, "REJECTED": StepRejected, "EXPIRED": StepExpired,
}

// Check reports where a started approval is now.
func (c *Client) Check(requestID string) (*Step, error) {
	s, err := c.Login.Status(requestID)
	if err != nil {
		return nil, err
	}
	state := stepStateMap[s.Status]
	if state == "" {
		state = StepWaiting
	}
	if s.Status == "PENDING" && s.RequiresPasskey {
		state = StepPasskeyRequired
	}
	step := &Step{State: state, RequestID: requestID}
	if state == StepApproved && s.Assurance != nil {
		step.Assurance = s.Assurance
	}
	return step, nil
}

// CompleteExpect is what Complete checks the approval is for.
type CompleteExpect struct {
	Details     []LoginDetail
	ReferenceID string
}

// Complete uses an approved request exactly once, after checking it is for
// this user, action and transaction. Call it right before doing the
// protected thing.
func (c *Client) Complete(requestID, user, action string, expect CompleteExpect) (*Approval, error) {
	res, err := c.Login.Consume(requestID)
	if err != nil {
		return nil, err
	}
	sameUser := strings.EqualFold(res.ExternalUsername, user)
	sameDetails := detailsDigest(expect.Details) == detailsDigest(res.Details)
	sameRef := res.ReferenceID == expect.ReferenceID
	if !sameUser || res.Type != action || !sameDetails || !sameRef {
		return nil, &ConfigError{Message: "touchque: this approval is for a different user, action or transaction."}
	}
	return &Approval{
		RequestID: requestID, User: res.ExternalUsername, Action: res.Type,
		Assurance: res.Assurance, ConfirmedVia: res.ConfirmedVia, ApprovalProof: res.ApprovalProof,
	}, nil
}

// ── Guard token ──────────────────────────────────────────────────────────
// The browser echoes this back while it waits. It is signed with a key
// derived from the API secret and binds the approval to one user, action and
// transaction, so it cannot be replayed for another user, amount or route.

type guardClaims struct {
	U   string `json:"u"`
	A   string `json:"a"`
	D   string `json:"d"`
	R   string `json:"r"`
	St  string `json:"st"`
	Rid string `json:"rid,omitempty"`
	N   string `json:"n,omitempty"`
	Oc  string `json:"oc,omitempty"`
	Exp int64  `json:"exp"`
}

func nowMs() int64 { return time.Now().UnixMilli() }

func tokenKey(apiSecret string) []byte {
	mac := hmac.New(sha256.New, []byte(apiSecret))
	mac.Write([]byte("touchque-guard-token-v1"))
	return mac.Sum(nil)
}

func b64u(b []byte) string {
	return strings.TrimRight(base64.URLEncoding.EncodeToString(b), "=")
}

func fromB64u(s string) ([]byte, error) {
	if m := len(s) % 4; m != 0 {
		s += strings.Repeat("=", 4-m)
	}
	return base64.URLEncoding.DecodeString(s)
}

func signGuardToken(apiSecret string, claims guardClaims) string {
	body, _ := json.Marshal(claims)
	bodyB64 := b64u(body)
	mac := hmac.New(sha256.New, tokenKey(apiSecret))
	mac.Write([]byte(bodyB64))
	return "v1." + bodyB64 + "." + b64u(mac.Sum(nil))
}

func verifyGuardToken(apiSecret, token string) *guardClaims {
	if token == "" || len(token) > 4096 {
		return nil
	}
	parts := strings.Split(token, ".")
	if len(parts) != 3 || parts[0] != "v1" {
		return nil
	}
	mac := hmac.New(sha256.New, tokenKey(apiSecret))
	mac.Write([]byte(parts[1]))
	expected := b64u(mac.Sum(nil))
	if !hmac.Equal([]byte(expected), []byte(parts[2])) {
		return nil
	}
	raw, err := fromB64u(parts[1])
	if err != nil {
		return nil
	}
	var claims guardClaims
	if err := json.Unmarshal(raw, &claims); err != nil {
		return nil
	}
	if claims.Exp < time.Now().UnixMilli() {
		return nil
	}
	return &claims
}
