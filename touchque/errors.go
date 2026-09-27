package touchque

import "fmt"

// APIError represents an error returned by the TouchQue API (status >= 400).
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
	Data       map[string]interface{}
}

func (e *APIError) Error() string {
	return fmt.Sprintf("TouchQue API Error (HTTP %d): %s", e.StatusCode, e.Message)
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

// PasskeyRequiredError means a phishing-resistant policy requires this
// request to be approved with a passkey — no push was sent.
type PasskeyRequiredError struct {
	RequestID string
}

func (e *PasskeyRequiredError) Error() string {
	return fmt.Sprintf("TouchQue: request %q must be approved with a passkey (phishing-resistant policy); no push was sent.", e.RequestID)
}
