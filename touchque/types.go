package touchque

import "time"

// GenerateSecretResponse represents the response from generating a new secret
type GenerateSecretResponse struct {
	Secret           string `json:"secret"`
	ExternalUsername string `json:"externalUsername"`
	ExpiresAt        string `json:"expiresAt"`
	TTLMs            int    `json:"ttlMs"`
	// QRCodeDataURL is a ready-to-render `data:image/png;base64,...` encoding
	// Secret for the Touchque mobile app to scan.
	QRCodeDataURL string   `json:"qrCodeDataUrl"`
	RecoveryCodes []string `json:"recoveryCodes"`
}

// ResetSecretResponse represents the response from resetting a secret
type ResetSecretResponse struct {
	Message          string   `json:"message"`
	UserID           string   `json:"userId"`
	Secret           string   `json:"secret"`
	ExternalUsername string   `json:"externalUsername"`
	ExpiresAt        string   `json:"expiresAt"`
	TTLMs            int      `json:"ttlMs"`
	QRCodeDataURL    string   `json:"qrCodeDataUrl"`
	RecoveryCodes    []string `json:"recoveryCodes"`
}

// LoginRequestResponse represents the response from initiating a login request
type LoginRequestResponse struct {
	RequestID     string `json:"requestId"`
	ChallengeCode string `json:"challengeCode"`
	Message       string `json:"message"`
	ExpiresAt     string `json:"expiresAt"`
	// CaseCode is the "Why?" case code of this decision (K7P-2QX). Show it to
	// the user ("Tell your support team: K7P-2QX"); your team opens the whole
	// decision (each check, the rule that matched, what would have let it
	// through) by this code in the dashboard (Logs → Look up a case).
	CaseCode string `json:"caseCode,omitempty"`
	// Reasons say why number matching or a passkey is needed (a fixed list,
	// never a score); empty for a plain push.
	Reasons []RiskReason `json:"reasons,omitempty"`
	// RequiresPasskey is true when a phishing-resistant policy demands a
	// passkey approval — no push was sent for this request.
	RequiresPasskey bool `json:"requiresPasskey,omitempty"`
	// TelemetryToken is set only when the integration has behavioral biometrics
	// enabled (TenantPolicy.behavioralBiometricsEnabled). Pass it plus RequestID
	// to your frontend to initialize the @touchque/web behavioral widget
	// (tq.behavioral.attach(...)). There is no widget in this server SDK.
	TelemetryToken string `json:"telemetryToken,omitempty"`
	// Canary is the Mirror Alarm probe: the page that shows this sign-in loads
	// its URL and sends a beacon to it (@touchque/web does both), so a
	// real-time phishing proxy in front of your site gets the approval refused
	// (webhook reason phishing_origin). Allow its host in your CSP.
	Canary *Canary `json:"canary,omitempty"`
	// Destination is set only when the request had one: whether the user used
	// it before and the earlier destinations it looks like.
	Destination *DestinationCheck `json:"destination,omitempty"`
}

// SecurityChanges says when the user's sign-in security last changed in your
// own system. A zero time is left out. Touchque adds what it saw itself;
// access rules and Actions read the minutes since each
// (minutesSince.mfaChange, .deviceChange, ...), e.g. refuse PAYOUT_CHANGE
// within 24 hours of a 2FA change.
type SecurityChanges struct {
	Password time.Time
	MFA      time.Time
	Device   time.Time
	Email    time.Time
	Phone    time.Time
}

// Destination is where an action sends money or value. The phone shows it in
// full in groups of four, with a warning when it looks like one the user used
// before but is not the same. Do not repeat it in Details.
type Destination struct {
	// Kind is iban, account, wallet, address or payee.
	Kind string `json:"kind"`
	// Value is the IBAN (its check digits must pass), account number, wallet
	// address, delivery address or payee name.
	Value string `json:"value"`
	// Known lists destinations of this kind the user already uses in your
	// system (saved payees, addresses); at most 50.
	Known []string `json:"known,omitempty"`
}

// DestinationLookalike is an earlier destination the request's one resembles.
type DestinationLookalike struct {
	Field string `json:"field"`
	// Reason is same_start_and_end, confusable, near_miss or mixed_script.
	Reason string `json:"reason"`
	// SimilarTo is the known destination, masked (TR33…1326).
	SimilarTo string `json:"similarTo,omitempty"`
}

// DestinationCheck is what Touchque made of a request's Destination.
type DestinationCheck struct {
	Known     bool                   `json:"known"`
	Lookalike []DestinationLookalike `json:"lookalike"`
}

// Canary is the Mirror Alarm probe of one login request.
type Canary struct {
	URL string `json:"url"`
}

// GetUserResponse is the link status of a user (Auth.GetUser). used flips true
// and DeviceID is set once the mobile app scans the setup secret.
type GetUserResponse struct {
	ExternalUsername string `json:"externalUsername"`
	DeviceID         string `json:"deviceId,omitempty"`
	Used             bool   `json:"used"`
	Frozen           bool   `json:"frozen"`
	CreatedAt        string `json:"createdAt"`
	ExpireAt         string `json:"expireAt,omitempty"`
	// Device is the linked phone's posture, or nil before a phone is linked.
	Device *DevicePosture `json:"device"`
}

// DevicePosture is what the Touchque app last reported about the phone it runs
// on, for device trust (GetUserResponse.Device). It is self-reported by the
// app; Signed says the phone's hardware approval key signed the latest report.
// An empty string means "not reported" (the API sends null).
//
// State is "compromised" (jailbroken/rooted or tampered), "unknown" (no report,
// or one older than 14 days), "at_risk" (no screen lock, approval keys
// destroyed, no hardware key, debugger or developer mode) or "healthy". Issues
// lists the reasons: jailbroken, tampered, integrity_failed, no_report,
// stale_report, no_screen_lock, keys_lost, no_hardware_key, debugger,
// developer_mode.
type DevicePosture struct {
	// Platform is "ios" or "android".
	Platform string `json:"platform,omitempty"`
	// Model is the hardware model, e.g. "iPhone15,3" or "Pixel 8".
	Model string `json:"model,omitempty"`
	// OSVersion is e.g. "18.1" or "15".
	OSVersion string `json:"osVersion,omitempty"`
	// SecurityPatch is the Android security patch level (YYYY-MM-DD); empty on iOS.
	SecurityPatch string `json:"securityPatch,omitempty"`
	AppVersion    string `json:"appVersion,omitempty"`
	// ScreenLock is nil when the phone did not say whether a passcode, PIN,
	// pattern or password is set.
	ScreenLock *bool `json:"screenLock"`
	// Biometrics is "face", "touch", "fingerprint", "iris" or "none".
	Biometrics string `json:"biometrics,omitempty"`
	// Jailbroken: jailbroken or rooted, by the app's checks.
	Jailbroken bool `json:"jailbroken"`
	// Compromised: jailbroken/rooted or tampered; sticky until the phone
	// reports clean for a cool-down.
	Compromised bool `json:"compromised"`
	// HardwareKey: approvals are signed by a Secure Enclave / Keystore key that
	// still works.
	HardwareKey bool `json:"hardwareKey"`
	// Attestation is "apple-appattest" or "android-key", how the hardware key
	// was proven genuine; empty when it was not attested.
	Attestation string `json:"attestation,omitempty"`
	// Signed: the latest report was signed by the phone's hardware key.
	Signed bool `json:"signed"`
	// ReportedAt is the ISO date-time of the latest report.
	ReportedAt string   `json:"reportedAt,omitempty"`
	LastSeenAt string   `json:"lastSeenAt,omitempty"`
	LinkedAt   string   `json:"linkedAt,omitempty"`
	State      string   `json:"state"`
	Issues     []string `json:"issues"`
}

// WebAuthnRegisterVerifyResponse is returned by WebAuthn.RegisterVerify.
type WebAuthnRegisterVerifyResponse struct {
	Verified     bool   `json:"verified"`
	CredentialID string `json:"credentialId"`
}

// WebAuthnAuthenticateVerifyResponse is returned by WebAuthn.AuthenticateVerify.
type WebAuthnAuthenticateVerifyResponse struct {
	Success bool   `json:"success"`
	Message string `json:"message"`
	// ExternalUsername is the user whose login request was approved, as
	// reported by Touchque (never by the browser). Empty on older APIs.
	ExternalUsername string `json:"externalUsername,omitempty"`
	// RequestID is the approved login request, when Touchque reports it.
	RequestID string `json:"requestId,omitempty"`
}

// WebAuthnPrimaryOptionsResponse is returned by WebAuthn.PrimaryOptions.
// WebAuthnPrimaryAvailability is returned by WebAuthn.PrimaryAvailability:
// whether passkey sign-in is on for your workspace. UserVerification is
// "required" or "preferred", or empty when Enabled is false.
type WebAuthnPrimaryAvailability struct {
	Enabled          bool   `json:"enabled"`
	UserVerification string `json:"userVerification"`
}

type WebAuthnPrimaryOptionsResponse struct {
	AttemptID string                 `json:"attemptId"`
	Options   map[string]interface{} `json:"options"`
}

// WebAuthnPrimaryVerifyResponse is returned by WebAuthn.PrimaryVerify. On
// Success the RequestID is a CONFIRMED LoginRequest; on !Success with
// RequiresStepUp, start the normal Login.Request / number-match flow instead.
type WebAuthnPrimaryVerifyResponse struct {
	Success          bool    `json:"success"`
	RequiresStepUp   bool    `json:"requiresStepUp,omitempty"`
	ExternalUsername string  `json:"externalUsername"`
	RiskScore        float64 `json:"riskScore"`
	RequestID        string  `json:"requestId,omitempty"`
}

// WebAuthnCredentialSummary is one entry from WebAuthn.ListCredentials.
type WebAuthnCredentialSummary struct {
	ID           string `json:"id"`
	CredentialID string `json:"credentialId"`
	DeviceType   string `json:"deviceType"`
	BackedUp     bool   `json:"backedUp"`
	Label        string `json:"label"`
	CreatedAt    string `json:"createdAt"`
	LastUsedAt   string `json:"lastUsedAt"`
}

// WebAuthnDeleteCredentialResponse is returned by WebAuthn.DeleteCredential.
type WebAuthnDeleteCredentialResponse struct {
	Deleted bool `json:"deleted"`
}

// LoginStatusResponse represents the response from checking login status.
type LoginStatusResponse struct {
	Status           string        `json:"status"`
	ExternalUsername string        `json:"externalUsername,omitempty"`
	Type             string        `json:"type,omitempty"`
	ReferenceID      string        `json:"referenceId,omitempty"`
	Details          []LoginDetail `json:"details,omitempty"`
	Consumed         bool          `json:"consumed,omitempty"`
	// RequiresPasskey: only a passkey can approve it — a phishing-resistant
	// policy, or the Vishing Shield moved it to a passkey at the phone tap
	// because the user was on a call (it is still PENDING then).
	RequiresPasskey bool       `json:"requiresPasskey,omitempty"`
	ConfirmedVia    string     `json:"confirmedVia,omitempty"`
	Assurance       *Assurance `json:"assurance,omitempty"`
	// ExpiresAt is the request's live expiry (ISO 8601): a Vishing Shield
	// escalation to a passkey extends it.
	ExpiresAt string `json:"expiresAt,omitempty"`
	// Reply: a request made with Reply, once the person typed it back (the
	// ciphertext only; OpenCodeReply opens it). nil for a CONFIRMED request
	// approved without typing (an older app).
	Reply *LoginReply `json:"reply,omitempty"`
	ShieldFields
}

// ShieldFields are the Vishing Shield fields of an approval. Provisional: it
// was given on the phone during a call; it stays CONFIRMED, but the user's
// critical actions are refused (blocked / provisional) until the phone
// re-confirms it after the call (ReconfirmedAt) or the user takes it back
// (Revoked, RevokeReason "COACHED" or "UNDO"). End what was built on a
// revoked approval.
type ShieldFields struct {
	Provisional   bool   `json:"provisional,omitempty"`
	ReconfirmedAt string `json:"reconfirmedAt,omitempty"`
	Revoked       bool   `json:"revoked,omitempty"`
	RevokeReason  string `json:"revokeReason,omitempty"`
}

// VerifyResponse represents the response from verifying a login request.
type VerifyResponse struct {
	Approved      bool       `json:"approved"`
	Status        string     `json:"status"`
	RequestID     string     `json:"requestId,omitempty"`
	ChallengeCode string     `json:"challengeCode,omitempty"`
	Assurance     *Assurance `json:"assurance,omitempty"`
	ConfirmedVia  string     `json:"confirmedVia,omitempty"`
	// Provisional: approved during a call (Vishing Shield); critical actions
	// wait until the phone re-confirms it.
	Provisional bool `json:"provisional,omitempty"`
}

// Assurance describes how a request was approved. PhishingResistant is true
// only for a passkey approval.
type Assurance struct {
	PhishingResistant bool   `json:"phishingResistant"`
	Method            string `json:"method"`
}

// ConsumeResponse is returned by Login.Consume: the approval, used exactly once.
type ConsumeResponse struct {
	Consumed         bool          `json:"consumed"`
	RequestID        string        `json:"requestId"`
	ExternalUsername string        `json:"externalUsername"`
	Type             string        `json:"type"`
	ReferenceID      string        `json:"referenceId,omitempty"`
	Details          []LoginDetail `json:"details,omitempty"`
	ConfirmedVia     string        `json:"confirmedVia,omitempty"`
	Assurance        *Assurance    `json:"assurance,omitempty"`
	ApprovalProof    interface{}   `json:"approvalProof,omitempty"`
	ShieldFields
}

// UnlinkSecretResponse represents the response from unlinking a device
type UnlinkSecretResponse struct {
	Success          bool   `json:"success"`
	ExternalUsername string `json:"externalUsername"`
	Message          string `json:"message"`
}

// ValidateSecretResponse represents the response from validating a setup secret
type ValidateSecretResponse struct {
	Valid            bool   `json:"valid"`
	ExternalUsername string `json:"externalUsername,omitempty"`
	IntegrationID    string `json:"integrationId,omitempty"`
	Message          string `json:"message,omitempty"`
	Reason           string `json:"reason,omitempty"`
	UsedAt           string `json:"usedAt,omitempty"`
	ExpiredAt        string `json:"expiredAt,omitempty"`
}
