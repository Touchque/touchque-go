package touchque

import (
	"context"
	"encoding/json"
	"net/url"
	"strings"
	"time"
)

// DefaultSSOBaseURL is the TouchQue SSO, where an organization's VPN (RADIUS)
// apps live. RadiusClient uses it when Config.BaseURL is empty.
const DefaultSSOBaseURL = "https://sso.touchque.com"

// RadiusClient talks to the RADIUS API of TouchQue SSO: the second factor for
// an organization's VPN and other RADIUS clients. The TouchQue RADIUS proxy
// (a program the organization runs in its own network) uses it; you only need
// it to build your own RADIUS server.
//
// The credential is the VPN app's proxy key and secret, created in the
// dashboard (Organization → VPN & RADIUS). Requests are signed with the
// secret like every TouchQue API request, so the secret never travels.
type RadiusClient struct {
	http   *httpClient
	secret string
}

// NewRadiusClient builds a RadiusClient. config.APIKey and config.APISecret
// are the VPN app's proxy key ("tq_rad_…") and secret; config.BaseURL is the
// TouchQue SSO (DefaultSSOBaseURL when empty). TimeoutMs defaults to 35000,
// above the longest wait the API holds a request for (25 s).
func NewRadiusClient(config *Config) (*RadiusClient, error) {
	cfg := *config
	if cfg.BaseURL == "" {
		cfg.BaseURL = DefaultSSOBaseURL
	}
	if cfg.TimeoutMs <= 0 {
		cfg.TimeoutMs = 35000
	}
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	if !strings.HasPrefix(cfg.APIKey, "tq_rad_") {
		return nil, &ConfigError{Message: "touchque: a RADIUS proxy key starts with 'tq_rad_' (Organization → VPN & RADIUS in the dashboard)"}
	}
	return &RadiusClient{http: newHTTPClient(&cfg), secret: cfg.APISecret}, nil
}

// RadiusProxyInfo is what the proxy says about itself when it fetches its
// app's settings; the dashboard shows it ("Proxy online, version …").
type RadiusProxyInfo struct {
	Version string `json:"version"`
	Host    string `json:"host,omitempty"`
	// Clients is how many RADIUS clients (VPN devices) the proxy's own
	// configuration lists.
	Clients int `json:"clients"`
	// PrimaryAuth is what the proxy's configuration checks the password
	// against: "radius", "ldap", "touchque" or "none".
	PrimaryAuth string `json:"primaryAuth,omitempty"`
}

// RadiusApp is a VPN app's settings, managed in the dashboard.
type RadiusApp struct {
	ID     string `json:"id"`
	Name   string `json:"name"`
	Status string `json:"status"` // "active" | "disabled"
	// Vendor is the VPN brand the admin picked (fortigate, cisco, paloalto,
	// openvpn, pfsense, opnsense, windows, other...).
	Vendor string `json:"vendor"`
	// PrimaryAuth: who checks the password. "directory" (the proxy, against
	// the company's RADIUS server or LDAP/Active Directory), "touchque" (the
	// TouchQue account password) or "none" (the VPN checked it already).
	PrimaryAuth string `json:"primaryAuth"`
	// Challenge: how the phone is asked. "number" (the VPN shows a number in
	// an Access-Challenge and the user types it on the phone) or "push" (a
	// plain approval, for VPNs that cannot show a challenge).
	Challenge string `json:"challenge"`
	// AllowedNAS: addresses or CIDR ranges of the VPN devices that may ask.
	// Empty: any device the proxy's configuration lists.
	AllowedNAS []string `json:"allowedNas"`
	// OutagePolicy: what the proxy does while it cannot reach TouchQue.
	// "closed" (refuse), "offline_codes" (accept a code from the TouchQue app,
	// checked against the outage cache) or "password_only" (the password alone).
	OutagePolicy string `json:"outagePolicy"`
	// UsernameDomain: the domain added to a bare user name ("jdoe" → jdoe@domain).
	UsernameDomain string `json:"usernameDomain,omitempty"`
	// Organization is the organization's display name.
	Organization string `json:"organization"`
}

// RadiusNAS is the VPN device that sent the RADIUS request.
type RadiusNAS struct {
	// IP is the address the request came from (or NAS-IP-Address).
	IP string `json:"ip"`
	// Identifier is NAS-Identifier, when sent.
	Identifier string `json:"identifier,omitempty"`
	// Name is the client's name in the proxy configuration.
	Name string `json:"name,omitempty"`
}

// RadiusEndUser is where the person signing in is, as the VPN reports it.
type RadiusEndUser struct {
	// IP is the person's public address, when Calling-Station-Id holds one.
	IP string `json:"ip,omitempty"`
	// CallingStationID is the raw Calling-Station-Id (an address or a MAC).
	CallingStationID string `json:"callingStationId,omitempty"`
}

// RadiusAuthRequest starts a VPN sign-in.
type RadiusAuthRequest struct {
	// Username is the name typed on the VPN (jdoe, jdoe@example.com, CORP\jdoe).
	Username string `json:"username"`
	// Email is the person's address from the directory (an LDAP "mail"
	// attribute), when the proxy knows it; it wins over Username.
	Email string `json:"email,omitempty"`
	// Password: only when the app's PrimaryAuth is "touchque".
	Password string `json:"password,omitempty"`
	// PrimaryVerified: the proxy checked the password against the company's
	// directory (PrimaryAuth "directory").
	PrimaryVerified bool `json:"primaryVerified,omitempty"`
	// Passcode is a code from the TouchQue app typed after the password
	// ("secret,123456"): no push is sent.
	Passcode string `json:"passcode,omitempty"`
	// ChallengeCapable false: this VPN device cannot show an Access-Challenge,
	// so it gets a plain push whatever the app's Challenge setting (nil: it can).
	ChallengeCapable *bool         `json:"challengeCapable,omitempty"`
	NAS              RadiusNAS     `json:"nas"`
	Client           RadiusEndUser `json:"client"`
}

// RadiusDecision is the answer to every RADIUS API call.
type RadiusDecision struct {
	// Decision: "accept", "reject", "challenge" (show Number and ask the user
	// to press OK; continue with Wait or Passcode) or "pending" (a push was
	// sent; continue with Wait).
	Decision      string `json:"decision"`
	TransactionID string `json:"transactionId,omitempty"`
	// Number is the number the user types on the phone (Decision "challenge").
	Number string `json:"number,omitempty"`
	// Reason is a machine-readable code (declined_on_phone, not_assigned,
	// number_match_needed, call_in_progress, ...).
	Reason string `json:"reason,omitempty"`
	// Message is English text for the user.
	Message string `json:"message,omitempty"`
	// CaseCode is the "Why?" case code (K7P-2QX) the user reads out to IT.
	CaseCode string `json:"caseCode,omitempty"`
	// Email is the TouchQue account the sign-in was for, when known.
	Email string `json:"email,omitempty"`
	// ExpiresIn is how many seconds the transaction stays open.
	ExpiresIn int `json:"expiresIn,omitempty"`
}

// Config fetches the app's settings (and tells TouchQue the proxy is up).
func (r *RadiusClient) Config(ctx context.Context, info RadiusProxyInfo) (*RadiusApp, error) {
	var out struct {
		App RadiusApp `json:"app"`
	}
	if err := r.call(ctx, "/sso/radius/v1/config", info, &out); err != nil {
		return nil, err
	}
	return &out.App, nil
}

// Authenticate starts a VPN sign-in: TouchQue checks the person, the app's
// groups and the organization's sign-in policy, then sends the push (or
// checks the passcode).
func (r *RadiusClient) Authenticate(ctx context.Context, req RadiusAuthRequest) (*RadiusDecision, error) {
	var out RadiusDecision
	if err := r.call(ctx, "/sso/radius/v1/auth", req, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// Wait holds the request until the phone answers or wait runs out (at most
// 25 s): "pending" then means the phone has not answered yet.
func (r *RadiusClient) Wait(ctx context.Context, transactionID string, wait time.Duration) (*RadiusDecision, error) {
	body := map[string]int64{"waitMs": wait.Milliseconds()}
	var out RadiusDecision
	if err := r.call(ctx, "/sso/radius/v1/transactions/"+url.PathEscape(transactionID)+"/wait", body, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// Passcode finishes a transaction with a code from the TouchQue app (when the
// phone has no internet) instead of the push.
func (r *RadiusClient) Passcode(ctx context.Context, transactionID, passcode string) (*RadiusDecision, error) {
	body := map[string]string{"passcode": passcode}
	var out RadiusDecision
	if err := r.call(ctx, "/sso/radius/v1/transactions/"+url.PathEscape(transactionID)+"/passcode", body, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func (r *RadiusClient) call(ctx context.Context, path string, body interface{}, out interface{}) error {
	res, err := r.http.postCtx(ctx, path, body)
	if err != nil {
		return err
	}
	raw, err := json.Marshal(res)
	if err != nil {
		return err
	}
	return json.Unmarshal(raw, out)
}
