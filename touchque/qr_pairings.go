package touchque

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"net/url"
	"regexp"
	"strings"
)

// QRPairingsResource pairs a browser by QR code: your page shows a QR code,
// the person scans it with the TouchQue app, and the phone that scanned is
// the one asked to approve.
//
//  1. Your page gets the thumbprint of its browser key (@touchque/web
//     browserKey.thumbprint()) and sends it to your server.
//  2. Create registers a pairing and returns URI (touchque://pair-browser?…):
//     show it as a QR code. It can be scanned once, for TTLSeconds (default
//     120). The nonce in it never leaves your server and the QR: TouchQue
//     keeps only its hash.
//  3. Poll Get: "scanned" once a phone holding one of your users' accounts
//     read it (ExternalUsername, Proximity), "confirmed" once the person went
//     on, "reported" when they said someone told them to scan it (their 2FA
//     freezes).
//  4. Login.RequestWithOptions with QRPairing asks that phone, once, with
//     number matching; the browser key's fingerprint is one of the rows the
//     phone signs. When your own checks say no, Refuse, and the phone shows why.
type QRPairingsResource struct {
	http *httpClient
}

func newQRPairingsResource(h *httpClient) *QRPairingsResource { return &QRPairingsResource{http: h} }

// QRPairingRefusalReasons is what Refuse may tell the phone.
var QRPairingRefusalReasons = []string{"policy", "device_not_approved", "too_many_browsers", "rate_limited", "no_account", "other"}

var b64url43 = regexp.MustCompile(`^[A-Za-z0-9_-]{43}$`)

// CreateQRPairingOptions registers a pairing for one browser.
type CreateQRPairingOptions struct {
	// KeyThumbprint is the RFC 7638 thumbprint of the browser's key, base64url.
	KeyThumbprint string
	// ClientIP and UserAgent are the end user's: the phone is told where the
	// browser is and whether it is on the same network.
	ClientIP  string
	UserAgent string
	// Browser ("Chrome 155") and OS ("macOS 15") are shown on the phone.
	Browser string
	OS      string
	// TTLSeconds is how long the QR code can be scanned: 30 to 300 (0 = 120).
	TTLSeconds int
}

// CreatedQRPairing is a registered pairing: show URI as a QR code.
type CreatedQRPairing struct {
	PairingID string `json:"pairingId"`
	ExpiresAt string `json:"expiresAt"`
	// Nonce is the one-time nonce in the QR code (TouchQue keeps its SHA-256).
	Nonce string `json:"nonce"`
	// URI is what the QR code says: touchque://pair-browser?v=1&p=…&n=…&k=….
	URI string `json:"uri"`
}

// QRPairingProximity says how near the phone was to the browser; Warnings
// holds "different_country" and "different_network".
type QRPairingProximity struct {
	SameNetwork *bool    `json:"sameNetwork"`
	SameCountry *bool    `json:"sameCountry"`
	Warnings    []string `json:"warnings"`
}

// QRPairingPlace is where the phone or the browser is.
type QRPairingPlace struct {
	Country  *string `json:"country"`
	Location *string `json:"location"`
}

// QRPairingOutcome is why a pairing was refused (by you, or declined on the phone).
type QRPairingOutcome struct {
	Reason     string  `json:"reason"`
	Message    string  `json:"message"`
	CaseCode   *string `json:"caseCode"`
	DeviceCode *string `json:"deviceCode"`
	At         string  `json:"at"`
}

// QRPairing is where a pairing stands. State: waiting, scanned, confirmed,
// requested, approved, refused, reported or expired. ExternalUsername,
// Proximity, Phone and Browser are set once a phone scanned it.
type QRPairing struct {
	PairingID        string              `json:"pairingId"`
	State            string              `json:"state"`
	KeyThumbprint    string              `json:"keyThumbprint"`
	ExpiresAt        string              `json:"expiresAt"`
	RequestID        *string             `json:"requestId"`
	ExternalUsername string              `json:"externalUsername,omitempty"`
	ScannedAt        string              `json:"scannedAt,omitempty"`
	ConfirmedAt      *string             `json:"confirmedAt,omitempty"`
	Phone            *QRPairingPlace     `json:"phone,omitempty"`
	Browser          *QRPairingPlace     `json:"browser,omitempty"`
	Proximity        *QRPairingProximity `json:"proximity,omitempty"`
	Outcome          *QRPairingOutcome   `json:"outcome,omitempty"`
	// ReportedAt: the person said someone told them to scan it; their 2FA is frozen.
	ReportedAt string `json:"reportedAt,omitempty"`
}

// RefuseQRPairingOptions is your own refusal: Message is what the phone shows
// (up to 300 characters); CaseCode and DeviceCode ("ABC-123") are optional.
type RefuseQRPairingOptions struct {
	Reason     string
	Message    string
	CaseCode   string
	DeviceCode string
}

// QRPairingURI is what the QR code says: touchque://pair-browser?v=1&p=<pairing>&n=<nonce>&k=<key thumbprint>.
func QRPairingURI(pairingID, nonce, keyThumbprint string) string {
	return "touchque://pair-browser?v=1&p=" + url.QueryEscape(pairingID) + "&n=" + url.QueryEscape(nonce) + "&k=" + url.QueryEscape(keyThumbprint)
}

// Create registers a pairing for one browser and returns the QR code's text.
func (r *QRPairingsResource) Create(ctx context.Context, opts CreateQRPairingOptions) (*CreatedQRPairing, error) {
	if !b64url43.MatchString(opts.KeyThumbprint) {
		return nil, &ConfigError{Message: "touchque: QRPairings.Create() needs KeyThumbprint: the RFC 7638 thumbprint of the browser key, base64url (43 characters)"}
	}
	if opts.TTLSeconds != 0 && (opts.TTLSeconds < 30 || opts.TTLSeconds > 300) {
		return nil, &ConfigError{Message: "touchque: QRPairings.Create(): TTLSeconds must be 30 to 300"}
	}
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return nil, &ConfigError{Message: "touchque: could not generate a nonce: " + err.Error()}
	}
	nonce := base64.RawURLEncoding.EncodeToString(raw)
	sum := sha256.Sum256([]byte(nonce))
	body := map[string]interface{}{"nonceHash": base64.RawURLEncoding.EncodeToString(sum[:]), "keyThumbprint": opts.KeyThumbprint}
	for k, v := range map[string]string{"clientIp": opts.ClientIP, "userAgent": opts.UserAgent, "browser": opts.Browser, "os": opts.OS} {
		if v != "" {
			body[k] = v
		}
	}
	if opts.TTLSeconds != 0 {
		body["ttlSeconds"] = opts.TTLSeconds
	}
	res, err := r.http.postCtx(ctx, "/qr-pairings", body)
	if err != nil {
		return nil, err
	}
	out := &CreatedQRPairing{}
	if err := remarshal(res, out); err != nil {
		return nil, err
	}
	out.Nonce = nonce
	out.URI = QRPairingURI(out.PairingID, nonce, opts.KeyThumbprint)
	return out, nil
}

// Get says where a pairing stands; once scanned, who scanned it and how near
// the phone was.
func (r *QRPairingsResource) Get(ctx context.Context, pairingID string) (*QRPairing, error) {
	if pairingID == "" {
		return nil, &ConfigError{Message: "touchque: QRPairings.Get() needs the pairing ID"}
	}
	return r.pairing(r.http.getWithQueryCtx(ctx, "/qr-pairings/"+url.PathEscape(pairingID), nil))
}

// Refuse tells the phone that your own checks refused a scanned pairing. Only
// a scanned or confirmed pairing can be refused (409 not_open otherwise).
func (r *QRPairingsResource) Refuse(ctx context.Context, pairingID string, opts RefuseQRPairingOptions) (*QRPairing, error) {
	if pairingID == "" {
		return nil, &ConfigError{Message: "touchque: QRPairings.Refuse() needs the pairing ID"}
	}
	known := false
	for _, reason := range QRPairingRefusalReasons {
		known = known || reason == opts.Reason
	}
	if !known {
		return nil, &ConfigError{Message: "touchque: QRPairings.Refuse(): Reason must be one of " + strings.Join(QRPairingRefusalReasons, ", ")}
	}
	if strings.TrimSpace(opts.Message) == "" {
		return nil, &ConfigError{Message: "touchque: QRPairings.Refuse() needs Message: what the phone shows (up to 300 characters)"}
	}
	body := map[string]interface{}{"reason": opts.Reason, "message": opts.Message}
	if opts.CaseCode != "" {
		body["caseCode"] = opts.CaseCode
	}
	if opts.DeviceCode != "" {
		body["deviceCode"] = opts.DeviceCode
	}
	return r.pairing(r.http.postCtx(ctx, "/qr-pairings/"+url.PathEscape(pairingID)+"/outcome", body))
}

func (r *QRPairingsResource) pairing(res map[string]interface{}, err error) (*QRPairing, error) {
	if err != nil {
		return nil, err
	}
	out := &QRPairing{}
	return out, remarshal(res, out)
}
