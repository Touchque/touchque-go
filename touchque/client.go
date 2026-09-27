package touchque

// Client is the main entry point for the TouchQue Go SDK.
type Client struct {
	Auth     *AuthResource
	Login    *LoginResource
	WebAuthn *WebAuthnResource
	Webhook  *WebhookResource
	Offline  *OfflineResource
	Actions  *ActionsResource

	apiSecret string
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
		Auth:      newAuthResource(httpWrapper),
		Login:     newLoginResource(httpWrapper),
		WebAuthn:  newWebAuthnResource(httpWrapper),
		Webhook:   newWebhookResource(config),
		Offline:   newOfflineResource(httpWrapper),
		Actions:   newActionsResource(httpWrapper),
		apiSecret: config.APISecret,
	}
}
