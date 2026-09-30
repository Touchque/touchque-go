package touchque

// OfflineResource is Offline Sign — QR challenge / typed code approvals that
// work with the phone offline (no internet on the device).
type OfflineResource struct {
	http *httpClient
}

func newOfflineResource(http *httpClient) *OfflineResource {
	return &OfflineResource{http: http}
}

// OfflineChallengeOptions holds every POST /offline/challenge field.
type OfflineChallengeOptions struct {
	ExternalUsername string
	Type             string // defaults to "LOGIN"
	// Details: shown on the phone (see LoginRequestOptions.Details). REQUIRED
	// for critical action types.
	Details    []LoginDetail
	ClientIP   string
	UserAgent  string
	TTLSeconds int // 30-300, default 120
	// SkipQRImage: set true to omit the ready-made QR image (QRDataURL comes
	// back empty) when you only need the raw QR text.
	SkipQRImage bool
	// RequestID is the push this QR is a fallback for: once the phone REJECTS
	// it the QR is dead (no new QR is issued, a code for the old one is refused
	// with reason "request_rejected"), and a push with number matching makes the
	// QR show the same number. Always set it when the QR follows a push.
	RequestID string
	// RequireNumberMatch asks for number matching on a standalone QR (implied
	// when RequestID points at a push that has one).
	RequireNumberMatch bool
}

// OfflineChallengeResponse is returned by Challenge.
type OfflineChallengeResponse struct {
	ChallengeID string `json:"challengeId"`
	// QR is the raw challenge text (TQ2.… — encrypted for the user's phone);
	// draw it as a QR code yourself if you don't use QRDataURL.
	QR string `json:"qr"`
	// QRDataURL is `data:image/png;base64,…`, ready for an <img> src; empty
	// when IncludeQRImage is false.
	QRDataURL        string `json:"qrDataUrl"`
	ExpiresAt        string `json:"expiresAt"`
	ExpiresInSeconds int    `json:"expiresInSeconds"`
	// TotpAvailable is true when the workspace allows the time-based code
	// fallback (no camera).
	TotpAvailable bool `json:"totpAvailable"`
	// ChallengeCode is the number to print under the QR (number matching).
	// Empty when the QR needs no number matching.
	ChallengeCode string `json:"challengeCode,omitempty"`
}

// Challenge issues an offline QR challenge.
func (o *OfflineResource) Challenge(opts OfflineChallengeOptions) (*OfflineChallengeResponse, error) {
	loginType := opts.Type
	if loginType == "" {
		loginType = "LOGIN"
	}
	body := map[string]interface{}{"externalUsername": opts.ExternalUsername, "type": loginType}
	if len(opts.Details) > 0 {
		body["details"] = opts.Details
	}
	if opts.ClientIP != "" {
		body["clientIp"] = opts.ClientIP
	}
	if opts.UserAgent != "" {
		body["userAgent"] = opts.UserAgent
	}
	if opts.TTLSeconds > 0 {
		body["ttlSeconds"] = opts.TTLSeconds
	}
	if opts.SkipQRImage {
		body["includeQrImage"] = false
	}
	if opts.RequestID != "" {
		body["requestId"] = opts.RequestID
	}
	if opts.RequireNumberMatch {
		body["requireNumberMatch"] = true
	}
	res, err := o.http.post("/offline/challenge", body)
	if err != nil {
		return nil, err
	}
	resp := &OfflineChallengeResponse{}
	if v, ok := res["challengeId"].(string); ok {
		resp.ChallengeID = v
	}
	if v, ok := res["qr"].(string); ok {
		resp.QR = v
	}
	if v, ok := res["qrDataUrl"].(string); ok {
		resp.QRDataURL = v
	}
	if v, ok := res["expiresAt"].(string); ok {
		resp.ExpiresAt = v
	}
	if v, ok := res["expiresInSeconds"].(float64); ok {
		resp.ExpiresInSeconds = int(v)
	}
	if v, ok := res["totpAvailable"].(bool); ok {
		resp.TotpAvailable = v
	}
	if v, ok := res["challengeCode"].(string); ok {
		resp.ChallengeCode = v
	}
	return resp, nil
}

// OfflineVerifyResult is common to Verify and VerifyTotp: never an error for
// a wrong/expired/used code — check Approved. Reason is one of invalid_code |
// locked | expired | used | unknown_challenge | request_rejected | too_many_failures |
// device_not_enrolled.
type OfflineVerifyResult struct {
	Approved         bool   `json:"approved"`
	Reason           string `json:"reason,omitempty"`
	AttemptsLeft     int    `json:"attemptsLeft,omitempty"`
	ChallengeID      string `json:"challengeId,omitempty"`
	ExternalUsername string `json:"externalUsername,omitempty"`
	Type             string `json:"type,omitempty"`
}

// Verify checks the 7-character code shown on the phone.
func (o *OfflineResource) Verify(challengeID, code string) (*OfflineVerifyResult, error) {
	return o.notApprovedAsResult(func() (map[string]interface{}, error) {
		return o.http.post("/offline/verify", map[string]interface{}{"challengeId": challengeID, "code": code})
	})
}

// VerifyTotp checks the rolling time-based code (no QR scan needed). Refused
// for critical action types.
func (o *OfflineResource) VerifyTotp(externalUsername, code, loginType, clientIP string) (*OfflineVerifyResult, error) {
	return o.VerifyTotpFor(externalUsername, code, loginType, clientIP, "")
}

// VerifyTotpFor is VerifyTotp for a sign-in that started with a push: requestID
// is that push, and a code is refused (reason "request_rejected") once the phone
// rejected it.
func (o *OfflineResource) VerifyTotpFor(externalUsername, code, loginType, clientIP, requestID string) (*OfflineVerifyResult, error) {
	if loginType == "" {
		loginType = "LOGIN"
	}
	body := map[string]interface{}{"externalUsername": externalUsername, "code": code, "type": loginType}
	if clientIP != "" {
		body["clientIp"] = clientIP
	}
	if requestID != "" {
		body["requestId"] = requestID
	}
	return o.notApprovedAsResult(func() (map[string]interface{}, error) {
		return o.http.post("/offline/totp/verify", body)
	})
}

func (o *OfflineResource) notApprovedAsResult(call func() (map[string]interface{}, error)) (*OfflineVerifyResult, error) {
	res, err := call()
	if err != nil {
		if apiErr, ok := err.(*APIError); ok && apiErr.StatusCode < 500 {
			r := &OfflineVerifyResult{Approved: false, AttemptsLeft: apiErr.AttemptsLeft}
			if apiErr.Reason != "" {
				r.Reason = apiErr.Reason
			} else if apiErr.Code != "" {
				r.Reason = apiErr.Code
			} else if e, ok := apiErr.Data["error"].(string); ok {
				r.Reason = e
			}
			return r, nil
		}
		return nil, err
	}
	resp := &OfflineVerifyResult{}
	if v, ok := res["approved"].(bool); ok {
		resp.Approved = v
	}
	if v, ok := res["challengeId"].(string); ok {
		resp.ChallengeID = v
	}
	if v, ok := res["externalUsername"].(string); ok {
		resp.ExternalUsername = v
	}
	if v, ok := res["type"].(string); ok {
		resp.Type = v
	}
	return resp, nil
}
