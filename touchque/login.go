package touchque

import (
	"log"
	"net/url"
	"strconv"
	"time"
)

// LoginResource handles sending 2FA requests and checking their status.
type LoginResource struct {
	http *httpClient
}

func newLoginResource(http *httpClient) *LoginResource {
	return &LoginResource{http: http}
}

// LoginDetail is one line of transaction context shown on the approval
// screen, e.g. {Label: "Amount", Value: "1,250.00 USD"}. Shown in order.
type LoginDetail struct {
	Label string `json:"label"`
	Value string `json:"value"`
}

// LoginRequestOptions holds every POST /login/request field. Use it with
// RequestWithOptions / VerifyWithOptions; Request and Verify keep their
// original positional signatures and cannot carry Details.
type LoginRequestOptions struct {
	ExternalUsername   string
	Type               string // defaults to "LOGIN"
	ReferenceID        string
	ClientIP           string // end user's IP: shown as "City, Country" on the phone
	UserAgent          string // end user's User-Agent: shown as browser + device
	RequireBiometric   bool
	RequireNumberMatch bool
	// Details: transaction context for the approval screen. At most 8
	// entries, labels <= 40 and values <= 120 characters; the API rejects
	// (never truncates) anything outside those limits. Build it from
	// server-side state, never from browser input.
	Details []LoginDetail
	// BrowserProof (silent sign-ins): the browser's device-bound key proof,
	// exactly as the browser sent it (the X-TouchQue-Browser header, made by
	// @touchque/web). When the user approves this request on the phone (or
	// with a passkey), TouchQue remembers the browser, so a later Risk.Check
	// can let the same browser in without asking. Pass it through untouched;
	// an invalid proof only means "a browser TouchQue does not know".
	BrowserProof string
	// Context is for your TouchQue Actions only (event.context): roles, plan,
	// amount… Any JSON object up to 4 KB. Never shown on the phone.
	Context map[string]interface{}
	// OnChallenge (VerifyWithOptions only) is called once, right after the
	// request is created and before any waiting: show ChallengeCode to the
	// user now; with number matching the phone asks for it. Not called when
	// only a passkey can approve. A panic in it is recovered and logged:
	// VerifyWithOptions keeps waiting.
	OnChallenge func(VerifyChallenge)
}

// VerifyChallenge is what OnChallenge receives as soon as the request exists.
type VerifyChallenge struct {
	RequestID string
	// ChallengeCode is the number to show when number matching is on ("" otherwise).
	ChallengeCode string
	ExpiresAt     string
	// Reasons say why number matching is needed (empty for a plain push).
	Reasons []RiskReason
	// CaseCode is the "Why?" case code of this decision.
	CaseCode string
}

// callOnChallenge runs the caller's callback; its panic is logged and never stops the wait.
func callOnChallenge(fn func(VerifyChallenge), c VerifyChallenge) {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("[TouchQue] OnChallenge failed: %v", r)
		}
	}()
	fn(c)
}

// Request sends a 2FA login/approval request to the user's mobile device.
func (l *LoginResource) Request(externalUsername string, loginType string, referenceID string, clientIP string, userAgent string, requireBiometric bool, requireNumberMatch bool) (*LoginRequestResponse, error) {
	return l.RequestWithOptions(LoginRequestOptions{
		ExternalUsername:   externalUsername,
		Type:               loginType,
		ReferenceID:        referenceID,
		ClientIP:           clientIP,
		UserAgent:          userAgent,
		RequireBiometric:   requireBiometric,
		RequireNumberMatch: requireNumberMatch,
	})
}

// RequestWithOptions sends a 2FA login/approval request with every option,
// including Details.
func (l *LoginResource) RequestWithOptions(opts LoginRequestOptions) (*LoginRequestResponse, error) {
	loginType := opts.Type
	if loginType == "" {
		loginType = "LOGIN"
	}
	payload := map[string]interface{}{
		"externalUsername": opts.ExternalUsername,
		"type":             loginType,
	}
	if opts.ReferenceID != "" {
		payload["referenceId"] = opts.ReferenceID
	}
	if opts.ClientIP != "" {
		payload["clientIp"] = opts.ClientIP
	}
	if opts.UserAgent != "" {
		payload["userAgent"] = opts.UserAgent
	}
	if opts.RequireBiometric {
		payload["requireBiometric"] = true
	}
	if opts.RequireNumberMatch {
		payload["requireNumberMatch"] = true
	}
	if len(opts.Details) > 0 {
		payload["details"] = opts.Details
	}
	if opts.BrowserProof != "" {
		payload["browserProof"] = opts.BrowserProof
	}
	if len(opts.Context) > 0 {
		payload["context"] = opts.Context
	}
	res, err := l.http.post("/login/request", payload)
	if err != nil {
		return nil, err
	}

	resp := &LoginRequestResponse{}
	if reqID, ok := res["requestId"].(string); ok {
		resp.RequestID = reqID
	}
	if challenge, ok := res["challengeCode"].(string); ok {
		resp.ChallengeCode = challenge
	}
	if msg, ok := res["message"].(string); ok {
		resp.Message = msg
	}
	if expAt, ok := res["expiresAt"].(string); ok {
		resp.ExpiresAt = expAt
	}
	if tok, ok := res["telemetryToken"].(string); ok {
		resp.TelemetryToken = tok
	}
	if rp, ok := res["requiresPasskey"].(bool); ok {
		resp.RequiresPasskey = rp
	}
	if canary, ok := res["canary"].(map[string]interface{}); ok {
		if u, ok := canary["url"].(string); ok && u != "" {
			resp.Canary = &Canary{URL: u}
		}
	}
	// "Why?": the decision's case code and, for a step-up, its plain reasons.
	if cc, ok := res["caseCode"].(string); ok {
		resp.CaseCode = cc
	}
	if list, ok := res["reasons"].([]interface{}); ok {
		for _, item := range list {
			if m, ok := item.(map[string]interface{}); ok {
				if code, ok := m["code"].(string); ok {
					text, _ := m["text"].(string)
					resp.Reasons = append(resp.Reasons, RiskReason{Code: code, Text: text})
				}
			}
		}
	}

	return resp, nil
}

// parseShieldFields reads the Vishing Shield fields of a status or consume
// answer (absent from servers before it: all zero).
func parseShieldFields(res map[string]interface{}) ShieldFields {
	var f ShieldFields
	f.Provisional, _ = res["provisional"].(bool)
	f.ReconfirmedAt, _ = res["reconfirmedAt"].(string)
	f.Revoked, _ = res["revoked"].(bool)
	f.RevokeReason, _ = res["revokeReason"].(string)
	return f
}

func parseAssurance(res map[string]interface{}) *Assurance {
	m, ok := res["assurance"].(map[string]interface{})
	if !ok {
		return nil
	}
	a := &Assurance{}
	if v, ok := m["phishingResistant"].(bool); ok {
		a.PhishingResistant = v
	}
	if v, ok := m["method"].(string); ok {
		a.Method = v
	}
	return a
}

func parseDetails(res map[string]interface{}) []LoginDetail {
	raw, ok := res["details"].([]interface{})
	if !ok {
		return nil
	}
	out := make([]LoginDetail, 0, len(raw))
	for _, item := range raw {
		m, ok := item.(map[string]interface{})
		if !ok {
			continue
		}
		d := LoginDetail{}
		if v, ok := m["label"].(string); ok {
			d.Label = v
		}
		if v, ok := m["value"].(string); ok {
			d.Value = v
		}
		out = append(out, d)
	}
	return out
}

// Status checks the current status of a login request.
func (l *LoginResource) Status(requestID string) (*LoginStatusResponse, error) {
	res, err := l.http.get("/login/status/" + url.PathEscape(requestID))
	if err != nil {
		return nil, err
	}

	resp := &LoginStatusResponse{}
	if status, ok := res["status"].(string); ok {
		resp.Status = status
	}
	if v, ok := res["externalUsername"].(string); ok {
		resp.ExternalUsername = v
	}
	if v, ok := res["type"].(string); ok {
		resp.Type = v
	}
	if v, ok := res["referenceId"].(string); ok {
		resp.ReferenceID = v
	}
	resp.Details = parseDetails(res)
	if v, ok := res["consumed"].(bool); ok {
		resp.Consumed = v
	}
	if v, ok := res["requiresPasskey"].(bool); ok {
		resp.RequiresPasskey = v
	}
	if v, ok := res["confirmedVia"].(string); ok {
		resp.ConfirmedVia = v
	}
	resp.Assurance = parseAssurance(res)
	resp.ShieldFields = parseShieldFields(res)

	return resp, nil
}

// Consume uses an approved request exactly once. The first call on a
// CONFIRMED request wins atomically; every later call (a replayed token, a
// retried form post) returns an *APIError with Code "already_used" (409).
func (l *LoginResource) Consume(requestID string) (*ConsumeResponse, error) {
	res, err := l.http.post("/login/"+url.PathEscape(requestID)+"/consume", map[string]interface{}{})
	if err != nil {
		return nil, err
	}
	resp := &ConsumeResponse{}
	if v, ok := res["consumed"].(bool); ok {
		resp.Consumed = v
	}
	if v, ok := res["requestId"].(string); ok {
		resp.RequestID = v
	}
	if v, ok := res["externalUsername"].(string); ok {
		resp.ExternalUsername = v
	}
	if v, ok := res["type"].(string); ok {
		resp.Type = v
	}
	if v, ok := res["referenceId"].(string); ok {
		resp.ReferenceID = v
	}
	resp.Details = parseDetails(res)
	if v, ok := res["confirmedVia"].(string); ok {
		resp.ConfirmedVia = v
	}
	resp.Assurance = parseAssurance(res)
	resp.ApprovalProof = res["approvalProof"]
	resp.ShieldFields = parseShieldFields(res)
	return resp, nil
}

// Verify sends a request and waits (polls) until the user approves or rejects it.
func (l *LoginResource) Verify(externalUsername string, loginType string, referenceID string, clientIP string, userAgent string, requireBiometric bool, requireNumberMatch bool, timeoutMs int) (*VerifyResponse, error) {
	return l.VerifyWithOptions(LoginRequestOptions{
		ExternalUsername:   externalUsername,
		Type:               loginType,
		ReferenceID:        referenceID,
		ClientIP:           clientIP,
		UserAgent:          userAgent,
		RequireBiometric:   requireBiometric,
		RequireNumberMatch: requireNumberMatch,
	}, timeoutMs)
}

// VerifyWithOptions is Verify with every request option, including Details
// and OnChallenge. With number matching (your RequireNumberMatch, a workspace
// policy or the risk engine can turn it on) the user must pick a number on
// the phone: show it from OnChallenge, which runs before the wait.
//
//	client.Login.VerifyWithOptions(touchque.LoginRequestOptions{
//		ExternalUsername: user, Type: "SEND_MONEY",
//		OnChallenge: func(c touchque.VerifyChallenge) {
//			if c.ChallengeCode != "" { show("Pick " + c.ChallengeCode + " on your phone") }
//		},
//	}, 30000)
func (l *LoginResource) VerifyWithOptions(opts LoginRequestOptions, timeoutMs int) (*VerifyResponse, error) {
	reqResult, err := l.RequestWithOptions(opts)
	if err != nil {
		return nil, err
	}

	reqID := reqResult.RequestID
	if reqID == "" {
		return nil, &APIError{Message: "Missing requestId in response"}
	}
	if reqResult.RequiresPasskey {
		return nil, &PasskeyRequiredError{RequestID: reqID}
	}
	// The number to show, before waiting: the phone asks the user for it.
	if opts.OnChallenge != nil {
		callOnChallenge(opts.OnChallenge, VerifyChallenge{
			RequestID: reqID, ChallengeCode: reqResult.ChallengeCode, ExpiresAt: reqResult.ExpiresAt,
			Reasons: reqResult.Reasons, CaseCode: reqResult.CaseCode,
		})
	}

	startTime := time.Now()
	pollInterval := 400 * time.Millisecond

	for {
		statusResult, err := l.Status(reqID)
		if err != nil {
			return nil, err
		}

		switch statusResult.Status {
		case "CONFIRMED":
			return &VerifyResponse{
				Approved:      true,
				Status:        statusResult.Status,
				RequestID:     reqID,
				ChallengeCode: reqResult.ChallengeCode,
				Assurance:     statusResult.Assurance,
				ConfirmedVia:  statusResult.ConfirmedVia,
				Provisional:   statusResult.Provisional,
			}, nil
		case "PENDING":
			// Vishing Shield: tapped during a call, the request now waits for a
			// passkey in the browser; polling would only run into the timeout.
			if statusResult.RequiresPasskey {
				return nil, &PasskeyRequiredError{RequestID: reqID, Reason: "step_up"}
			}
		case "REJECTED":
			return nil, &RejectedError{Message: "Request " + reqID + " was rejected by the user."}
		case "EXPIRED":
			return nil, &TimeoutError{Message: "Request " + reqID + " expired before it was approved."}
		}

		if time.Since(startTime).Milliseconds() > int64(timeoutMs) {
			return nil, &TimeoutError{Message: "Login verification timed out after " + strconv.Itoa(timeoutMs) + "ms"}
		}

		time.Sleep(pollInterval)
	}
}

// ApproveWithRecoveryCodeResponse represents the response when approving a request via recovery code
type ApproveWithRecoveryCodeResponse struct {
	Success bool   `json:"success"`
	Message string `json:"message"`
}

// ApproveWithRecoveryCode approves a pending 2FA request using a Recovery Code (bypasses mobile device).
func (l *LoginResource) ApproveWithRecoveryCode(requestID string, code string) (*ApproveWithRecoveryCodeResponse, error) {
	payload := map[string]interface{}{
		"requestId": requestID,
		"code":      code,
	}
	res, err := l.http.post("/login/recovery", payload)
	if err != nil {
		return nil, err
	}

	resp := &ApproveWithRecoveryCodeResponse{}
	// BUG FIX (found while adding tests): the real API returns `success` as a
	// JSON boolean (matching the Node/Python/PHP SDKs) — this was previously
	// asserted as `.(string)`, which always fails against a real boolean
	// response, silently leaving Success as its zero value forever.
	if success, ok := res["success"].(bool); ok {
		resp.Success = success
	}
	if msg, ok := res["message"].(string); ok {
		resp.Message = msg
	}

	return resp, nil
}

// Fraud reasons accepted by ReportFraud.
const (
	FraudChargeback        = "chargeback"
	FraudAccountTakeover   = "account_takeover"
	FraudSocialEngineering = "social_engineering"
	FraudOther             = "other"
)

// ReportFraudOptions describes why a request is being reported.
type ReportFraudOptions struct {
	// Reason is one of the Fraud* constants (default FraudOther).
	Reason string
	// Note is free text for your audit log, at most 500 characters.
	Note string
}

// ReportFraudResponse is the answer to ReportFraud.
type ReportFraudResponse struct {
	Reported bool `json:"reported"`
	// AlreadyReported is true when this request had already been reported.
	AlreadyReported bool   `json:"alreadyReported"`
	RequestID       string `json:"requestId"`
}

// ReportFraud reports a request you later learned was fraud — a chargeback,
// a confirmed account takeover, a scam the user was talked into. TouchQue's
// risk engine learns from it (it is the strongest signal it gets) and the
// report is kept in your audit log. The request's status does not change.
// Safe to call more than once: a repeat answers AlreadyReported.
func (l *LoginResource) ReportFraud(requestID string, opts ReportFraudOptions) (*ReportFraudResponse, error) {
	if requestID == "" {
		return nil, &ConfigError{Message: "ReportFraud needs the request id"}
	}
	payload := map[string]interface{}{}
	if opts.Reason != "" {
		payload["reason"] = opts.Reason
	}
	if opts.Note != "" {
		payload["note"] = opts.Note
	}
	res, err := l.http.post("/login/"+url.PathEscape(requestID)+"/report-fraud", payload)
	if err != nil {
		return nil, err
	}
	resp := &ReportFraudResponse{}
	resp.Reported, _ = res["reported"].(bool)
	resp.AlreadyReported, _ = res["alreadyReported"].(bool)
	resp.RequestID, _ = res["requestId"].(string)
	return resp, nil
}
