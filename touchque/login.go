package touchque

import (
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

	return resp, nil
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

// VerifyWithOptions is Verify with every request option, including Details.
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
			}, nil
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
