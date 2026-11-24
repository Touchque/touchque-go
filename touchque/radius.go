package touchque

import (
	"context"
	"encoding/json"
	"net/url"
	"strings"
	"time"
)

// DefaultSSOBaseURL is the Touchque SSO, where an organization's VPN (RADIUS)
// apps live. RadiusClient uses it when Config.BaseURL is empty.
const DefaultSSOBaseURL = "https://sso.touchque.com"

// RadiusClient talks to the RADIUS API of Touchque SSO: the second factor for
// an organization's VPN and other RADIUS clients. The Touchque RADIUS proxy
// (a program the organization runs in its own network) uses it; you only need
// it to build your own RADIUS server.
//
// The credential is the VPN app's proxy key and secret, created in the
// dashboard (Organization → VPN & RADIUS). Requests are signed with the
// secret like every Touchque API request, so the secret never travels.
type RadiusClient struct {
	http   *httpClient
	secret string
}

// NewRadiusClient builds a RadiusClient. config.APIKey and config.APISecret
// are the VPN app's proxy key ("tq_rad_…") and secret; config.BaseURL is the
// Touchque SSO (DefaultSSOBaseURL when empty). TimeoutMs defaults to 35000,
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
	// Touchque account password) or "none" (the VPN checked it already).
	PrimaryAuth string `json:"primaryAuth"`
	// Challenge: how the phone is asked. "number" (the VPN shows a number in
	// an Access-Challenge and the user types it on the phone) or "push" (a
	// plain approval, for VPNs that cannot show a challenge).
	Challenge string `json:"challenge"`
	// AllowedNAS: addresses or CIDR ranges of the VPN devices that may ask.
	// Empty: any device the proxy's configuration lists.
	AllowedNAS []string `json:"allowedNas"`
	// OutagePolicy: what the proxy does while it cannot reach Touchque.
	// "closed" (refuse), "offline_codes" (accept a code from the Touchque app,
	// checked against the outage cache) or "password_only" (the password alone).
	OutagePolicy string `json:"outagePolicy"`
	// UsernameDomain: the domain added to a bare user name ("jdoe" → jdoe@domain).
	UsernameDomain string `json:"usernameDomain,omitempty"`
	// Organization is the organization's display name.
	Organization string `json:"organization"`
	// OfflinePacks: a Windows sign-in app's offline sign-in packs (nil: off).
	// After an approved sign-in on a computer's own screen, the connector asks
	// for the next Size offline sign-ins there, valid Days (OfflinePack).
	OfflinePacks *RadiusOfflinePacks `json:"offlinePacks,omitempty"`
}

// RadiusOfflinePacks is how many offline sign-ins a computer keeps and for how long.
type RadiusOfflinePacks struct {
	Size int `json:"size"`
	Days int `json:"days"`
}

// RadiusOfflinePackRequest asks for a computer's offline sign-ins right after
// an approved Windows sign-in there.
type RadiusOfflinePackRequest struct {
	// TransactionID is the accepted sign-in's transaction.
	TransactionID string `json:"transactionId"`
	// MachineID is the computer's id (16-32 hex characters, kept by the connector).
	MachineID string `json:"machineId"`
	Computer  string `json:"computer"`
	// Account is the Windows account the person signed in to.
	Account string `json:"account"`
	// Have is how many unused slots the computer still holds for the account.
	Have int `json:"have"`
}

// RadiusOfflineSlot is one offline sign-in: the slow digest of its
// 10-character code and the QR only the person's phone opens.
type RadiusOfflineSlot struct {
	Index      int    `json:"index"`
	Salt       string `json:"salt"`
	Digest     string `json:"digest"`
	QR         string `json:"qr"`
	QRTerminal string `json:"qrTerminal"`
}

// RadiusOfflineKDF is how the slot digests were made (PBKDF2-SHA256).
type RadiusOfflineKDF struct {
	Name       string `json:"name"`
	Iterations int    `json:"iterations"`
	Length     int    `json:"length"`
}

// RadiusOfflinePack is a computer's new offline sign-ins for a person (no
// slots, and Reason, when none were due or allowed).
type RadiusOfflinePack struct {
	Email   string `json:"email"`
	Account string `json:"account"`
	Scope   struct {
		ID    string `json:"id"`
		Name  string `json:"name"`
		Epoch string `json:"epoch"`
	} `json:"scope"`
	ValidUntil time.Time           `json:"validUntil"`
	CodeLength int                 `json:"codeLength"`
	KDF        RadiusOfflineKDF    `json:"kdf"`
	Slots      []RadiusOfflineSlot `json:"slots"`
	Reason     string              `json:"reason,omitempty"`
}

// RadiusOfflineUse is a slot the computer accepted while it had no network.
type RadiusOfflineUse struct {
	Index   int       `json:"index"`
	At      time.Time `json:"at"`
	Session string    `json:"session,omitempty"`
}

// RadiusOfflinePackState is one person's pack on the computer, for OfflinePackSync.
type RadiusOfflinePackState struct {
	Email   string             `json:"email"`
	Account string             `json:"account"`
	Used    []RadiusOfflineUse `json:"used,omitempty"`
}

// RadiusOfflineSyncRequest is what the computer holds and used.
type RadiusOfflineSyncRequest struct {
	MachineID string                   `json:"machineId"`
	Computer  string                   `json:"computer"`
	Packs     []RadiusOfflinePackState `json:"packs"`
}

// RadiusOfflineSyncResult says which packs the computer keeps ("keep") or
// drops ("delete"), and whether the computer was revoked.
type RadiusOfflineSyncResult struct {
	Revoked bool `json:"revoked"`
	Packs   []struct {
		Email  string `json:"email"`
		Action string `json:"action"`
		Reason string `json:"reason,omitempty"`
	} `json:"packs"`
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
	// Passcode is a code from the Touchque app typed after the password
	// ("secret,123456"): no push is sent.
	Passcode string `json:"passcode,omitempty"`
	// ChallengeCapable false: this VPN device cannot show an Access-Challenge,
	// so it gets a plain push whatever the app's Challenge setting (nil: it can).
	ChallengeCapable *bool `json:"challengeCapable,omitempty"`
	// TerminalQR: the client draws a QR in a terminal (the Touchque PAM module
	// on a Linux server). Touchque then also returns QR and QRTerminal: a
	// compact QR for a phone without internet, whose 7-character code goes to
	// Passcode like a time-based code. Only for apps with vendor "linux".
	TerminalQR bool          `json:"terminalQr,omitempty"`
	NAS        RadiusNAS     `json:"nas"`
	Client     RadiusEndUser `json:"client"`
}

// RadiusDecision is the answer to every RADIUS API call.
type RadiusDecision struct {
	// Decision: "accept", "reject", "challenge" (show Number and ask the user
	// to press OK; continue with Wait or Passcode), "pending" (a push was
	// sent; continue with Wait) or, only for a sign-in started with
	// TerminalQR, "retry" (the code was wrong: ask again and continue the
	// same transaction with Passcode or Wait).
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
	// Email is the Touchque account the sign-in was for, when known.
	Email string `json:"email,omitempty"`
	// ExpiresIn is how many seconds the transaction stays open.
	ExpiresIn int `json:"expiresIn,omitempty"`
	// QR is the compact QR text ("TQ3:...") for a phone without internet,
	// returned with "challenge" or "pending" when the sign-in asked for
	// TerminalQR and the person's phone can do offline approvals.
	QR string `json:"qr,omitempty"`
	// QRTerminal is QR drawn with Unicode half blocks, lines separated by
	// "\n": print it as it is.
	QRTerminal string `json:"qrTerminal,omitempty"`
	// AttemptsLeft: how many more codes the transaction takes ("retry").
	AttemptsLeft int `json:"attemptsLeft,omitempty"`
}

// Config fetches the app's settings (and tells Touchque the proxy is up).
func (r *RadiusClient) Config(ctx context.Context, info RadiusProxyInfo) (*RadiusApp, error) {
	var out struct {
		App RadiusApp `json:"app"`
	}
	if err := r.call(ctx, "/sso/radius/v1/config", info, &out); err != nil {
		return nil, err
	}
	return &out.App, nil
}

// Authenticate starts a VPN sign-in: Touchque checks the person, the app's
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

// Passcode finishes a transaction with a code from the Touchque app (when the
// phone has no internet) instead of the push.
func (r *RadiusClient) Passcode(ctx context.Context, transactionID, passcode string) (*RadiusDecision, error) {
	body := map[string]string{"passcode": passcode}
	var out RadiusDecision
	if err := r.call(ctx, "/sso/radius/v1/transactions/"+url.PathEscape(transactionID)+"/passcode", body, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// OfflinePack asks for a computer's offline sign-ins after an approved Windows
// sign-in there (a Windows sign-in app with OfflinePacks).
func (r *RadiusClient) OfflinePack(ctx context.Context, req RadiusOfflinePackRequest) (*RadiusOfflinePack, error) {
	var out RadiusOfflinePack
	if err := r.call(ctx, "/sso/radius/v1/offline-packs", req, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// OfflinePackSync sends the slots used offline and learns which packs the computer keeps.
func (r *RadiusClient) OfflinePackSync(ctx context.Context, req RadiusOfflineSyncRequest) (*RadiusOfflineSyncResult, error) {
	var out RadiusOfflineSyncResult
	if err := r.call(ctx, "/sso/radius/v1/offline-packs/sync", req, &out); err != nil {
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
