package touchque

import (
	"context"
	"net/url"
	"regexp"
	"strconv"
	"strings"
)

// DeviceRiskResource is Device risk (a paid add-on, off until your workspace
// turns it on): a visitor ID for every browser on your sign-up,
// password-reset, sign-in or approval page.
//
// The page identifies with @touchque/web (deviceRisk.identify({ siteKey,
// purpose }) gives { visitorId, requestId, confidence }) and sends you the
// requestId. Never trust the page's copy: read the identification here
// (GetEvent) or check it for an account (Check). TouchQue keeps keyed hashes
// only, with a key of your workspace alone, and its risk engine decides.
//
// Every signal only ever asks for more: StepUp means an extra check on this
// page (an emailed code, a passkey, a number-matched approval), never a
// refusal. For sign-ins, pass the requestId as DeviceRiskRequestId in
// LoginRequestOptions and RiskCheckOptions instead. Collect it only on these
// pages and name it in your privacy notice.
//
// With the script tag (device.js), the form arrives with touchque_request_id:
//
//	r, err := tq.DeviceRisk.Check(ctx, touchque.DeviceRiskCheckOptions{RequestID: req.FormValue("touchque_request_id"), ExternalUsername: email})
//
// Pass it as it came. Missing, empty, made up or expired, it is still a
// verdict (Report missing, unknown, expired; the signal
// device_identification_missing), never an error: a page without the tag, or
// with it blocked, only gets the visitor a step-up.
type DeviceRiskResource struct {
	http *httpClient
}

func newDeviceRiskResource(h *httpClient) *DeviceRiskResource { return &DeviceRiskResource{http: h} }

// DeviceRiskEvents are the pages a device report may come from.
var DeviceRiskEvents = []string{"sign_in", "sign_up", "password_reset", "approval"}

// DeviceRiskReports are what the page had sent: ok, replayed, or no usable identification.
var DeviceRiskReports = []string{"ok", "replayed", "missing", "unknown", "expired", "invalid"}

var deviceRiskRequestID = regexp.MustCompile(`^dre_[A-Za-z0-9_-]{22}$`)

// DeviceRiskCheckOptions is one page's identification, for an account.
type DeviceRiskCheckOptions struct {
	// RequestID is the touchque_request_id form field (the script tag) or
	// deviceRisk.identify()'s requestId, as it came: empty is answered Report "missing".
	RequestID string
	// DeviceRisk is instead the page's report (deviceRisk.collect()), relayed untouched.
	DeviceRisk string
	// Event is the page: sign_in (default), sign_up, password_reset or approval.
	Event string
	// ExternalUsername is the account the page is for, when there is one. One account per identification.
	ExternalUsername string
	// ClientIP is the end user's address; default: where the browser identified from.
	ClientIP string
}

// DeviceRiskSignal is one signal. Each one only ever asks for more.
type DeviceRiskSignal struct {
	// Code: device_tampered, device_virtual, device_geo_mismatch,
	// device_many_accounts, device_signup_burst, device_id_resets,
	// device_many_countries, device_wrong_site, device_report_replayed,
	// device_private_window (context only), device_step_up_by_admin,
	// device_identification_missing (no identification, or one that does not verify).
	Code string
	Text string
	// Strength is what a step-up for it should be: number_match, passkey, or none (context only).
	Strength string
	// Enforced: scored now; false means reported only (shadow) until TouchQue enforces it.
	Enforced bool
	Evidence map[string]interface{}
}

// DeviceRiskCheckResult is the answer.
type DeviceRiskCheckResult struct {
	// Report is what the page had sent: ok; replayed (another account, or sent
	// twice); or no usable identification, which raises
	// device_identification_missing: missing (none or empty), unknown (made up,
	// or another workspace's), expired (over 15 minutes old), invalid (a relayed
	// report that cannot be read).
	Report    string
	RequestID string
	// VisitorID (tqv_…) is this browser in your workspace only.
	VisitorID  string
	Confidence float64
	// Visitor holds firstSeenAt, lastSeenAt, seenCount, matchedBy, sealed, status (your admin's mark), labels.
	Visitor map[string]interface{}
	Counts  map[string]interface{}
	// Network is the address as the risk engine saw it (never coordinates):
	// countryCode, region, city, accuracyKm, timeZone, asn, asnOrg, type
	// (isp, hosting, tor, unknown), tor, hosting, hostingProvider, timezoneMismatch.
	Network map[string]interface{}
	// Velocity holds the visitor's counts: accounts24h, accounts30d,
	// signUps24h, countries24h, idResets7d, identifications1h, identifications24h.
	Velocity map[string]interface{}
	// Bot is one answer to "a bot?": result (detected, suspected,
	// not_detected) and reasons.
	Bot     map[string]interface{}
	Signals []DeviceRiskSignal
	// StepUp: ask for more on this page. Never a reason to refuse.
	StepUp bool
	// WouldStepUp: a signal that asks was raised, enforced or not.
	WouldStepUp bool
	// Requires is none, number_match or passkey.
	Requires string
	// Mode is enforce when at least one raised signal is enforced, else shadow.
	Mode string
	// Engine is the engine's state for this check; "unavailable" when the risk engine could not be reached and the verdict is a safe default (empty when the answer carries none).
	Engine string
	// CaseCode opens the decision record ("Why?") in the dashboard.
	CaseCode string
}

// ParseDeviceRiskCheck reads an answer, failing toward asking: StepUp is true
// unless it says exactly false; junk signals are dropped.
func ParseDeviceRiskCheck(res map[string]interface{}) *DeviceRiskCheckResult {
	out := &DeviceRiskCheckResult{Report: "invalid", Signals: []DeviceRiskSignal{}, StepUp: true, Requires: "none", Mode: "shadow"}
	if res == nil {
		return out
	}
	if r, _ := res["report"].(string); r != "" {
		for _, known := range DeviceRiskReports {
			if r == known {
				out.Report = r
			}
		}
	}
	out.RequestID, _ = res["requestId"].(string)
	out.VisitorID, _ = res["visitorId"].(string)
	out.Confidence, _ = res["confidence"].(float64)
	out.Visitor, _ = res["visitor"].(map[string]interface{})
	out.Counts, _ = res["counts"].(map[string]interface{})
	out.Network, _ = res["network"].(map[string]interface{})
	out.Velocity, _ = res["velocity"].(map[string]interface{})
	out.Bot, _ = res["bot"].(map[string]interface{})
	out.CaseCode, _ = res["caseCode"].(string)
	out.Engine, _ = res["engine"].(string)
	list, _ := res["signals"].([]interface{})
	for _, raw := range list {
		s, ok := raw.(map[string]interface{})
		if !ok {
			continue
		}
		code, ok := s["code"].(string)
		if !ok {
			continue
		}
		text, _ := s["text"].(string)
		strength, _ := s["strength"].(string)
		if strength != "passkey" && strength != "none" {
			strength = "number_match"
		}
		evidence, _ := s["evidence"].(map[string]interface{})
		enforced, _ := s["enforced"].(bool)
		out.Signals = append(out.Signals, DeviceRiskSignal{Code: code, Text: text, Strength: strength, Enforced: enforced, Evidence: evidence})
	}
	if v, ok := res["stepUp"].(bool); ok && !v {
		out.StepUp = false
	}
	out.WouldStepUp, _ = res["wouldStepUp"].(bool)
	if r, _ := res["requires"].(string); r == "number_match" || r == "passkey" {
		out.Requires = r
	}
	if m, _ := res["mode"].(string); m == "enforce" {
		out.Mode = "enforce"
	}
	return out
}

// Check checks the page's identification for an account: it binds it (one
// account per identification, 15 minutes) and asks the risk engine. Pass the
// form field as it came: empty or made up is still a verdict (Report missing,
// unknown), never an error. 409 device_risk_off until your workspace turns
// Device risk on.
//
//	r, err := tq.DeviceRisk.Check(ctx, touchque.DeviceRiskCheckOptions{RequestID: req.FormValue("touchque_request_id"), Event: "sign_up", ExternalUsername: email, ClientIP: ip})
//	if err == nil && r.StepUp { askForEmailCode() } // never refuse on it alone
func (dr *DeviceRiskResource) Check(ctx context.Context, opts DeviceRiskCheckOptions) (*DeviceRiskCheckResult, error) {
	event := opts.Event
	if event == "" {
		event = "sign_in"
	}
	known := false
	for _, e := range DeviceRiskEvents {
		known = known || e == event
	}
	if !known {
		return nil, &ConfigError{Message: "touchque: DeviceRisk.Check() Event must be one of " + strings.Join(DeviceRiskEvents, ", ")}
	}
	body := map[string]interface{}{"event": event}
	if opts.RequestID != "" {
		id := opts.RequestID
		if len(id) > 64 {
			id = id[:64]
		}
		body["requestId"] = id
	} else if opts.DeviceRisk != "" {
		body["deviceRisk"] = opts.DeviceRisk
	}
	if opts.ExternalUsername != "" {
		body["externalUsername"] = opts.ExternalUsername
	}
	if opts.ClientIP != "" {
		body["clientIp"] = opts.ClientIP
	}
	res, err := dr.http.postCtx(ctx, "/device-risk/check", body)
	if err != nil {
		return nil, err
	}
	return ParseDeviceRiskCheck(res), nil
}

// DeviceRiskSearchOptions are SearchEvents' filters. From/To are YYYY-MM-DD
// (UTC) or ISO times (7 days before To by default, at most 90 days, within your
// retention). IP is an address or a CIDR range and is never returned. StepUp
// filters only when set. Cursor is the previous page's NextCursor, as it came.
// Limit is 1 to 100 (0: the default 25).
type DeviceRiskSearchOptions struct {
	From, To, Signal, Kind, Origin, IP, Account, VisitorID, RequestID, Cursor string
	StepUp                                                                    *bool
	Limit                                                                     int
}

// DeviceRiskSearchResult is one page of SearchEvents: pass NextCursor back as
// Cursor until it is empty. Each event has no address and no raw trait.
type DeviceRiskSearchResult struct {
	Events     []map[string]interface{}
	NextCursor string
	From, To   string
}

// SearchEvents searches your workspace's identifications, newest first, one
// page at a time (GET /device-risk/events). Do not page by moving From/To. A
// search that would read too much is a 422 search_too_broad: narrow the range
// or add a filter.
func (dr *DeviceRiskResource) SearchEvents(ctx context.Context, opts DeviceRiskSearchOptions) (*DeviceRiskSearchResult, error) {
	if opts.Limit != 0 && (opts.Limit < 1 || opts.Limit > 100) {
		return nil, &ConfigError{Message: "touchque: DeviceRisk.SearchEvents() Limit must be 1 to 100"}
	}
	params := map[string]string{}
	for k, v := range map[string]string{"from": opts.From, "to": opts.To, "signal": opts.Signal, "kind": opts.Kind, "origin": opts.Origin,
		"ip": opts.IP, "account": opts.Account, "visitorId": opts.VisitorID, "requestId": opts.RequestID, "cursor": opts.Cursor} {
		if v != "" {
			params[k] = v
		}
	}
	if opts.StepUp != nil {
		params["stepUp"] = strconv.FormatBool(*opts.StepUp)
	}
	if opts.Limit != 0 {
		params["limit"] = strconv.Itoa(opts.Limit)
	}
	res, err := dr.http.getWithQueryCtx(ctx, "/device-risk/events", params)
	if err != nil {
		return nil, err
	}
	out := &DeviceRiskSearchResult{Events: []map[string]interface{}{}}
	if list, ok := res["events"].([]interface{}); ok {
		for _, e := range list {
			if m, ok := e.(map[string]interface{}); ok {
				out.Events = append(out.Events, m)
			}
		}
	}
	out.NextCursor, _ = res["nextCursor"].(string)
	out.From, _ = res["from"].(string)
	out.To, _ = res["to"].(string)
	return out, nil
}

// GetEvent reads the trusted identification behind a requestId: the visitor
// (visitorId, confidence, matchedBy), what the page showed (facts) and the
// risk engine's verdict. Read-only.
func (dr *DeviceRiskResource) GetEvent(ctx context.Context, requestID string) (map[string]interface{}, error) {
	if !deviceRiskRequestID.MatchString(requestID) {
		return nil, &ConfigError{Message: "touchque: DeviceRisk.GetEvent() needs a requestId (dre_…)"}
	}
	return dr.http.getWithQueryCtx(ctx, "/device-risk/events/"+url.PathEscape(requestID), nil)
}
