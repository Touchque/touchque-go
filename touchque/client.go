package touchque

import "log/slog"

// Client is the main entry point for the TouchQue Go SDK.
type Client struct {
	Auth     *AuthResource
	Login    *LoginResource
	WebAuthn *WebAuthnResource
	Webhook  *WebhookResource
	Offline  *OfflineResource
	// ActionTypes: what users approve (LOGIN, SEND_MONEY…). Was Actions before v4.
	ActionTypes *ActionTypesResource
	// Actions is TouchQue Actions: your own code in the approval pipeline.
	Actions *ActionsResource
	// Risk is silent sign-ins: should this sign-in ask the phone, and which
	// browsers TouchQue knows.
	Risk *RiskResource
	// Recovery is Never Locked Out: move a user whose phone is gone to a new
	// phone, with colleagues vouching.
	Recovery *RecoveryResource
	// Assist is the help desk: IT working on a person's account in the open,
	// and checks on their phone before sensitive actions.
	Assist *AssistResource
	// Agents manages AI agents as identities of their own: register (public
	// key), suspend, revoke, kill switch. The agent itself uses NewAgent.
	Agents *AgentsResource
	// Identity is the TouchQue Login Management API: your customers' accounts,
	// roles, organizations, apps and connections.
	Identity *IdentityResource
	// Mobile is the Mobile SDK: your own iOS/Android app approves for your
	// users (enrollment tokens, devices, settings).
	Mobile *MobileResource
	// QRPairings pairs a browser by QR code: the phone that scans it is the
	// one asked to approve.
	QRPairings *QRPairingsResource
	// DeviceRisk is Device risk: the device on your sign-up, reset, sign-in
	// or approval page (a paid add-on).
	DeviceRisk *DeviceRiskResource
	// SafeGuard is Safe Guard: Safe transactions approved on the approver's
	// phone, for TouchQueSafeGuard.
	SafeGuard *SafeGuardResource

	apiSecret string
	logger    *slog.Logger
}

// NewClient initializes a new TouchQue SDK Client with the given
// configuration. Panics on invalid configuration (matches this SDK's
// long-standing behavior) — use New() for a version that returns an error instead.
func NewClient(config *Config) *Client {
	config.sanitize()
	return newClient(config)
}

// New builds a Client from TQ_API_KEY / TQ_API_SECRET / TQ_API_URL, or from
// config if given (config[0], at most one).
func New(config ...*Config) (*Client, error) {
	var cfg *Config
	if len(config) > 0 && config[0] != nil {
		cfg = config[0]
		if err := cfg.Validate(); err != nil {
			return nil, err
		}
	} else {
		c, err := ConfigFromEnv()
		if err != nil {
			return nil, err
		}
		cfg = c
	}
	return newClient(cfg), nil
}

func newClient(config *Config) *Client {
	httpWrapper := newHTTPClient(config)

	return &Client{
		logger:      config.Logger,
		Auth:        newAuthResource(httpWrapper),
		Login:       newLoginResource(httpWrapper),
		WebAuthn:    newWebAuthnResource(httpWrapper),
		Webhook:     newWebhookResource(config),
		Offline:     newOfflineResource(httpWrapper),
		ActionTypes: newActionTypesResource(httpWrapper),
		Actions:     newActionsResource(httpWrapper),
		Risk:        newRiskResource(httpWrapper),
		Recovery:    newRecoveryResource(httpWrapper),
		Assist:      newAssistResource(httpWrapper),
		Agents:      newAgentsResource(httpWrapper),
		Identity:    newIdentityResource(httpWrapper),
		Mobile:      newMobileResource(httpWrapper),
		QRPairings:  newQRPairingsResource(httpWrapper),
		DeviceRisk:  newDeviceRiskResource(httpWrapper),
		SafeGuard:   newSafeGuardResource(httpWrapper),
		apiSecret:   config.APISecret,
	}
}
