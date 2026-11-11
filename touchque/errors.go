package touchque

import (
	"errors"
	"fmt"
)

// APIError represents an error returned by the Touchque API (status >= 400).
type APIError struct {
	StatusCode int
	Message    string
	// Code is the machine-readable error code (e.g. "device_not_linked",
	// "unknown_action"), when the API sent one.
	Code string
	// Reason: offline sign only — why a code was not approved.
	Reason string
	// AttemptsLeft: offline sign only — wrong codes left before the challenge locks.
	AttemptsLeft int
	// RetryAfter: seconds to wait before retrying (429 / 423).
	RetryAfter int
	// CaseCode is the "Why?" case code of a refusal (K7P-2QX): show it to the
	// user ("Tell your support team: K7P-2QX"); your team opens the decision by
	// it in the dashboard. Empty for other errors.
	CaseCode string
	// Feature is the catalog id (device_risk, ai_agents, mobile_sdk, ciam…) of
	// a feature refusal; see ErrFeatureNotInPlan. Empty for other errors.
	Feature string
	Data    map[string]interface{}
}

func (e *APIError) Error() string {
	return fmt.Sprintf("Touchque API Error (HTTP %d): %s", e.StatusCode, e.Message)
}

// The organization behind your workspace cannot use a feature here (HTTP
// 403). An *APIError matches one of these with errors.Is, and ErrFeature for
// any of the three; its Feature field names the feature:
//   - ErrFeatureNotInPlan: not in its plan (feature_not_in_plan); an owner or
//     admin adds it in the Touchque dashboard;
//   - ErrFeatureReadOnly: being turned off (feature_read_only); reads still
//     work for 14 days, changes are refused;
//   - ErrFeatureOff: switched off on this Touchque deployment (feature_off).
var (
	ErrFeature          = errors.New("touchque: feature not available")
	ErrFeatureNotInPlan = errors.New("touchque: feature not in the organization's plan")
	ErrFeatureReadOnly  = errors.New("touchque: feature is being turned off (read-only)")
	ErrFeatureOff       = errors.New("touchque: feature switched off on this deployment")
)

var featureErrors = map[string]error{
	"feature_not_in_plan": ErrFeatureNotInPlan,
	"feature_read_only":   ErrFeatureReadOnly,
	"feature_off":         ErrFeatureOff,
}

// Is lets errors.Is match the feature sentinels.
func (e *APIError) Is(target error) bool {
	code, _ := e.Data["error"].(string)
	sentinel, ok := featureErrors[code]
	if !ok {
		return false
	}
	return target == ErrFeature || target == sentinel
}

// NetworkError means the request never reached the API (DNS, connection, timeout).
type NetworkError struct {
	Message string
}

func (e *NetworkError) Error() string {
	return e.Message
}

// ConfigError means invalid or missing configuration, or an undefined action type.
type ConfigError struct {
	Message string
}

func (e *ConfigError) Error() string {
	return e.Message
}

// TimeoutError represents a timeout during a polling operation, or a request
// that expired before it was approved.
type TimeoutError struct {
	Message string
}

func (e *TimeoutError) Error() string {
	return e.Message
}

// RejectedError represents an explicit rejection by the user.
type RejectedError struct {
	Message string
}

func (e *RejectedError) Error() string {
	return e.Message
}

// WebhookSignatureError represents an invalid or replayed webhook.
type WebhookSignatureError struct {
	Message string
}

func (e *WebhookSignatureError) Error() string {
	return e.Message
}

// WebhookReplayError means a correctly signed webhook with this `jti` was
// already accepted (see WebhookResource.VerifyWithOptions).
type WebhookReplayError struct {
	JTI string
}

func (e *WebhookReplayError) Error() string {
	return "Webhook was already accepted (replayed jti)"
}

// PasskeyRequiredError means this request must be approved with a passkey.
// Reason is "" or "policy" when a phishing-resistant policy requires it (no
// push was sent), or "step_up" when the user tapped Approve on the phone
// during a call (Vishing Shield) and the request, still open, now waits for a
// passkey in the browser.
type PasskeyRequiredError struct {
	RequestID string
	Reason    string
}

func (e *PasskeyRequiredError) Error() string {
	if e.Reason == "step_up" {
		return fmt.Sprintf("Touchque: request %q must now be approved with a passkey: the user approved on the phone during a call.", e.RequestID)
	}
	return fmt.Sprintf("Touchque: request %q must be approved with a passkey (phishing-resistant policy); no push was sent.", e.RequestID)
}

// ApprovalError means an AI agent's approval ended without a usable approval:
// Status is rejected, blocked, revoked, expired, stale (approved too long ago)
// or redeemed (already used).
type ApprovalError struct {
	ApprovalID string
	Status     string
	Reason     string
}

func (e *ApprovalError) Error() string {
	if e.Reason != "" {
		return fmt.Sprintf("Touchque: approval %q is %s (%s)", e.ApprovalID, e.Status, e.Reason)
	}
	return fmt.Sprintf("Touchque: approval %q is %s", e.ApprovalID, e.Status)
}

// ApprovalMismatchError means an approval token does not say what you are
// about to execute (another person, action type, amount, recipient…), or it
// is not a valid token from Touchque. Do not execute.
type ApprovalMismatchError struct {
	Message string
}

func (e *ApprovalMismatchError) Error() string { return "Touchque: " + e.Message }
