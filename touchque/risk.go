package touchque

import "context"

// RiskResource is silent sign-ins: ask TouchQue's risk engine whether a
// sign-in needs the phone at all, and manage the browsers it knows for a user.
//
// A browser becomes known when the user approves a request on the phone (or
// with a passkey) that carried the browser's device-bound key proof
// (LoginRequestOptions.BrowserProof). Later, Check with a fresh proof from the
// same browser answers Prompt == false when nothing about the sign-in is new.
// Check sends nothing to the phone.
type RiskResource struct {
	http *httpClient
}

func newRiskResource(http *httpClient) *RiskResource {
	return &RiskResource{http: http}
}

// RiskCheckOptions holds every POST /risk/check field.
type RiskCheckOptions struct {
	// ExternalUsername is the user in YOUR system. Required.
	ExternalUsername string
	// Type is the action the user is about to do (the API's default is
	// "LOGIN"). A critical action always asks.
	Type string
	// ClientIP is the end user's address: compared with the networks of the
	// user's earlier approved sign-ins.
	ClientIP  string
	UserAgent string
	// BrowserProof is the browser's device-bound key proof (the
	// X-TouchQue-Browser header, made by @touchque/web), passed through
	// untouched.
	BrowserProof string
	// MaxAgeSeconds is your own limit on how long ago the last phone approval
	// in this browser may be, in seconds; 0 = always ask. nil leaves it to
	// TouchQue, which never goes beyond its own limit (7 days).
	MaxAgeSeconds *int
}

// RiskReason is one reason behind a Check answer. Show Text or translate Code.
//
// Why it was silent: known_browser, recent_approval, same_phone,
// familiar_network, no_risk_signal. Why it asks: no_browser_key, new_browser,
// approval_too_old, policy_every_sign_in, other_phone, new_country,
// new_network, network_unknown, hosting_network, critical_action,
// sensitive_action, risk_signal, push_fatigue, fraud_report, new_factor,
// vishing_shield, checks_incomplete, silent_mode_shadow, phone_not_linked,
// frozen, and more: new codes are added in minor versions.
type RiskReason struct {
	Code string `json:"code"`
	// Text is English.
	Text string `json:"text"`
}

// RiskCheckResult is the answer to Check.
type RiskCheckResult struct {
	// Prompt is false only when TouchQue answered exactly prompt: false:
	// nothing about this sign-in is new, let the user in without a push.
	// Anything else (including an unreadable answer) is true: ask on the
	// phone as usual.
	Prompt  bool         `json:"prompt"`
	Reasons []RiskReason `json:"reasons"`
	// Assurance is how sure TouchQue is that this is the user: "high",
	// "normal" (the default) or "low".
	Assurance string `json:"assurance"`
	// SilentMode is "enforce" or "shadow". In shadow mode silent sign-ins are
	// only measured for this workspace: Prompt is always true and the
	// reasons say what would have happened.
	SilentMode string `json:"silentMode"`
}

// RiskBrowsersOptions selects whose browsers Browsers lists.
type RiskBrowsersOptions struct {
	ExternalUsername string
}

// RiskBrowser is a browser TouchQue knows for a user: one the user approved
// on the phone (or with a passkey). Times are ISO 8601; "" when unset.
type RiskBrowser struct {
	// Thumbprint is the RFC 7638 thumbprint of the browser's key: pass it to
	// ForgetBrowsers to forget this one.
	Thumbprint string `json:"thumbprint"`
	Label      string `json:"label,omitempty"`
	CreatedAt  string `json:"createdAt,omitempty"`
	// LastMfaAt is the last phone or passkey approval in this browser.
	LastMfaAt string `json:"lastMfaAt,omitempty"`
	// LastMfaMethod is how that approval was given, e.g. "push" or "passkey".
	LastMfaMethod string `json:"lastMfaMethod,omitempty"`
	LastSeenAt    string `json:"lastSeenAt,omitempty"`
	// LastSilentAt is the last sign-in TouchQue let through without asking.
	LastSilentAt string `json:"lastSilentAt,omitempty"`
}

// RiskBrowsersResponse is the answer to Browsers.
type RiskBrowsersResponse struct {
	Browsers []RiskBrowser `json:"browsers"`
}

// ForgetBrowsersOptions selects the browsers ForgetBrowsers forgets.
type ForgetBrowsersOptions struct {
	ExternalUsername string
	// Thumbprint forgets one browser; leave it empty to forget every browser
	// of the user (e.g. after a password reset).
	Thumbprint string
}

// ForgetBrowsersResponse is the answer to ForgetBrowsers.
type ForgetBrowsersResponse struct {
	Forgotten int `json:"forgotten"`
}

// parseRiskCheck reads a POST /risk/check answer, failing closed: Prompt is
// false ONLY when the answer says exactly prompt: false (a JSON boolean).
// Reason entries without a string code are dropped (a malformed reasons
// field is []), an unknown or missing assurance is "normal", and a silent
// mode other than "shadow" is "enforce".
func parseRiskCheck(raw interface{}) *RiskCheckResult {
	body, _ := raw.(map[string]interface{})
	res := &RiskCheckResult{Prompt: true, Reasons: []RiskReason{}, Assurance: "normal", SilentMode: "enforce"}
	if p, ok := body["prompt"].(bool); ok && !p {
		res.Prompt = false
	}
	if list, ok := body["reasons"].([]interface{}); ok {
		for _, item := range list {
			m, ok := item.(map[string]interface{})
			if !ok {
				continue
			}
			code, ok := m["code"].(string)
			if !ok {
				continue
			}
			text, _ := m["text"].(string)
			res.Reasons = append(res.Reasons, RiskReason{Code: code, Text: text})
		}
	}
	switch a, _ := body["assurance"].(string); a {
	case "high", "normal", "low":
		res.Assurance = a
	}
	if m, _ := body["silentMode"].(string); m == "shadow" {
		res.SilentMode = "shadow"
	}
	return res
}

// Check asks whether this sign-in needs the phone. It sends nothing to the
// phone. Skip the push only when Prompt is false; on any error, ask as usual.
//
//	proof := r.Header.Get(touchque.GuardBrowserHeader)
//	risk, err := tq.Risk.Check(r.Context(), touchque.RiskCheckOptions{ExternalUsername: user, ClientIP: ip, BrowserProof: proof})
//	if err == nil && !risk.Prompt {
//	    return openSession(user) // known browser, nothing new
//	}
//	step, err := tq.Start("LOGIN", user, touchque.StartOptions{IP: ip, BrowserProof: proof})
func (rr *RiskResource) Check(ctx context.Context, opts RiskCheckOptions) (*RiskCheckResult, error) {
	if opts.ExternalUsername == "" {
		return nil, &ConfigError{Message: "touchque: Risk.Check() needs the user (ExternalUsername)"}
	}
	body := map[string]interface{}{"externalUsername": opts.ExternalUsername}
	if opts.Type != "" {
		body["type"] = opts.Type
	}
	if opts.ClientIP != "" {
		body["clientIp"] = opts.ClientIP
	}
	if opts.UserAgent != "" {
		body["userAgent"] = opts.UserAgent
	}
	if opts.BrowserProof != "" {
		body["browserProof"] = opts.BrowserProof
	}
	if opts.MaxAgeSeconds != nil {
		body["maxAgeSeconds"] = *opts.MaxAgeSeconds
	}
	res, err := rr.http.postCtx(ctx, "/risk/check", body)
	if err != nil {
		return nil, err
	}
	return parseRiskCheck(res), nil
}

// Browsers lists the browsers TouchQue knows for a user (for an "approved
// browsers" list in your settings page).
func (rr *RiskResource) Browsers(ctx context.Context, opts RiskBrowsersOptions) (*RiskBrowsersResponse, error) {
	if opts.ExternalUsername == "" {
		return nil, &ConfigError{Message: "touchque: Risk.Browsers() needs the user (ExternalUsername)"}
	}
	res, err := rr.http.getWithQueryCtx(ctx, "/risk/browsers", map[string]string{"externalUsername": opts.ExternalUsername})
	if err != nil {
		return nil, err
	}
	out := &RiskBrowsersResponse{Browsers: []RiskBrowser{}}
	list, _ := res["browsers"].([]interface{})
	for _, item := range list {
		m, ok := item.(map[string]interface{})
		if !ok {
			continue
		}
		b := RiskBrowser{}
		b.Thumbprint, _ = m["thumbprint"].(string)
		b.Label, _ = m["label"].(string)
		b.CreatedAt, _ = m["createdAt"].(string)
		b.LastMfaAt, _ = m["lastMfaAt"].(string)
		b.LastMfaMethod, _ = m["lastMfaMethod"].(string)
		b.LastSeenAt, _ = m["lastSeenAt"].(string)
		b.LastSilentAt, _ = m["lastSilentAt"].(string)
		out.Browsers = append(out.Browsers, b)
	}
	return out, nil
}

// ForgetBrowsers forgets one browser (Thumbprint) or all of a user's
// browsers: their next sign-in asks the phone again. Call it after a
// password reset or when the user signs out everywhere.
func (rr *RiskResource) ForgetBrowsers(ctx context.Context, opts ForgetBrowsersOptions) (*ForgetBrowsersResponse, error) {
	if opts.ExternalUsername == "" {
		return nil, &ConfigError{Message: "touchque: Risk.ForgetBrowsers() needs the user (ExternalUsername)"}
	}
	body := map[string]interface{}{"externalUsername": opts.ExternalUsername}
	if opts.Thumbprint != "" {
		body["thumbprint"] = opts.Thumbprint
	}
	res, err := rr.http.postCtx(ctx, "/risk/browsers/forget", body)
	if err != nil {
		return nil, err
	}
	out := &ForgetBrowsersResponse{}
	if n, ok := res["forgotten"].(float64); ok {
		out.Forgotten = int(n)
	}
	return out, nil
}
