package touchque

// GenerateSecretResponse represents the response from generating a new secret
type GenerateSecretResponse struct {
	Secret           string `json:"secret"`
	ExternalUsername string `json:"externalUsername"`
	ExpiresAt        string `json:"expiresAt"`
	TTLMs            int    `json:"ttlMs"`
	// QRCodeDataURL is a ready-to-render `data:image/png;base64,...` encoding
	// Secret for the TouchQue mobile app to scan.
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
	QRCodeDataURL    string   `json:"qrCodeDataUrl"`
	RecoveryCodes    []string `json:"recoveryCodes"`
}

// LoginRequestResponse represents the response from initiating a login request
type LoginRequestResponse struct {
	RequestID     string `json:"requestId"`
	ChallengeCode string `json:"challengeCode"`
	Message       string `json:"message"`
	ExpiresAt     string `json:"expiresAt"`
	// RequiresPasskey is true when a phishing-resistant policy demands a
	// passkey approval — no push was sent for this request.
	RequiresPasskey bool `json:"requiresPasskey,omitempty"`
	// TelemetryToken is set only when the integration has behavioral biometrics
	// enabled (TenantPolicy.behavioralBiometricsEnabled). Pass it plus RequestID
	// to your frontend to initialize the @touchque/web behavioral widget
	// (tq.behavioral.attach(...)). There is no widget in this server SDK.
	TelemetryToken string `json:"telemetryToken,omitempty"`
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
}

// WebAuthnPrimaryOptionsResponse is returned by WebAuthn.PrimaryOptions.
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
	RequiresPasskey  bool          `json:"requiresPasskey,omitempty"`
	ConfirmedVia     string        `json:"confirmedVia,omitempty"`
	Assurance        *Assurance    `json:"assurance,omitempty"`
}

// VerifyResponse represents the response from verifying a login request.
type VerifyResponse struct {
	Approved      bool       `json:"approved"`
	Status        string     `json:"status"`
	RequestID     string     `json:"requestId,omitempty"`
	ChallengeCode string     `json:"challengeCode,omitempty"`
	Assurance     *Assurance `json:"assurance,omitempty"`
	ConfirmedVia  string     `json:"confirmedVia,omitempty"`
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
