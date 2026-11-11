package touchque

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"time"
)

// What a RADIUS proxy keeps for a Touchque outage: everyone who may use the
// VPN now, with salted, slow digests of their next ~4 hours of codes from the
// Touchque app (never a key), so a code typed on the VPN can be checked while
// Touchque cannot be reached. Touchque SSO signs every page with the app's
// proxy secret; check it with OpenOutagePage before using a page.

// outageSignContext is what the page signature covers before the payload.
const outageSignContext = "touchque-outage-cache.v1:"

// RadiusOutageCacheRequest asks for one page of the outage cache.
type RadiusOutageCacheRequest struct {
	// HaveUntil is the last step the proxy holds for everyone in Have: they
	// get only the steps after it, everyone else the whole window.
	HaveUntil int64    `json:"haveUntil,omitempty"`
	Have      []string `json:"have,omitempty"`
	// After is the previous page's Next (empty: the first page).
	After string `json:"after,omitempty"`
}

// RadiusOutagePage is one page as it arrives; keep it as it is to check it
// again later (OpenOutagePage).
type RadiusOutagePage struct {
	Payload   string `json:"payload"`
	Signature string `json:"signature"`
}

// RadiusOutageUser is one person's digests for the steps FromStep onwards.
type RadiusOutageUser struct {
	ID       string `json:"id"`
	Email    string `json:"email"`
	FromStep int64  `json:"fromStep"`
	Salt     string `json:"salt"`
	// Digests: base64, KDF.Length bytes each, two per step from FromStep.
	Digests string `json:"digests"`
}

// RadiusOutageCache is an opened page.
type RadiusOutageCache struct {
	V   int    `json:"v"`
	App string `json:"app"`
	// Policy is the app's OutagePolicy when the page was made: "closed",
	// "offline_codes" or "password_only".
	Policy      string    `json:"policy"`
	IssuedAt    time.Time `json:"issuedAt"`
	StepSeconds int64     `json:"stepSeconds"`
	// Until is the last step any digest covers: nothing is accepted after it.
	Until int64 `json:"until"`
	// Domains are tried after a bare user name ("jdoe" → jdoe@domain).
	Domains []string `json:"domains"`
	KDF     *struct {
		Name       string `json:"name"`
		Iterations int    `json:"iterations"`
		Length     int    `json:"length"`
	} `json:"kdf"`
	// Members: on the first page only (nil on the others), everyone who may
	// sign in now. Drop anyone else at once.
	Members []string           `json:"members"`
	Users   []RadiusOutageUser `json:"users"`
	// Next is the After of the next page; empty: this was the last.
	Next string `json:"next"`
	// Unavailable: why no codes came (the workspace has outage codes turned off).
	Unavailable string `json:"unavailable,omitempty"`
}

// OutageCache fetches one page of the outage cache.
func (r *RadiusClient) OutageCache(ctx context.Context, req RadiusOutageCacheRequest) (*RadiusOutagePage, error) {
	var out RadiusOutagePage
	if err := r.call(ctx, "/sso/radius/v1/outage-cache", req, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// ErrOutagePageSignature: the page was not signed with this app's proxy
// secret (changed on the way or on disk, or the secret was renewed).
var ErrOutagePageSignature = errors.New("touchque: the outage cache page is not signed with this proxy secret")

// OpenOutagePage checks a page's signature with the client's secret and reads it.
func (r *RadiusClient) OpenOutagePage(p *RadiusOutagePage) (*RadiusOutageCache, error) {
	return OpenOutagePage(r.secret, p)
}

// OpenOutagePage checks a page's signature with the proxy secret and reads it.
func OpenOutagePage(secret string, p *RadiusOutagePage) (*RadiusOutageCache, error) {
	if p == nil {
		return nil, ErrOutagePageSignature
	}
	want, err := hex.DecodeString(p.Signature)
	if err != nil {
		return nil, ErrOutagePageSignature
	}
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(outageSignContext + p.Payload))
	if !hmac.Equal(mac.Sum(nil), want) {
		return nil, ErrOutagePageSignature
	}
	raw, err := base64.StdEncoding.DecodeString(p.Payload)
	if err != nil {
		return nil, err
	}
	var c RadiusOutageCache
	if err := json.Unmarshal(raw, &c); err != nil {
		return nil, err
	}
	return &c, nil
}

// MatchOutageCode checks a typed code against one run of digests (salt and
// digests as base64, as RadiusOutageUser has them), at the current step or
// one either side and never after until. It returns the step it belongs to.
// Accept each step once: refuse codes for a step at or before the last one
// accepted for the person.
func MatchOutageCode(salt, digests string, fromStep, until int64, iterations, length int, stepSeconds int64, code string, at time.Time) (int64, bool) {
	given, ok := normalizeOfflineCode(code)
	if !ok || stepSeconds <= 0 || length <= 0 {
		return 0, false
	}
	s, err := base64.StdEncoding.DecodeString(salt)
	if err != nil {
		return 0, false
	}
	d, err := base64.StdEncoding.DecodeString(digests)
	if err != nil {
		return 0, false
	}
	return matchDigests(d, s, fromStep, until, iterations, length, given, at.Unix()/stepSeconds)
}

// RadiusOutageEvent is one decision the proxy made while Touchque could not
// be reached, sent when it can again.
type RadiusOutageEvent struct {
	// ID is random hex (16-64 characters): a resend writes nothing twice.
	ID       string    `json:"id"`
	At       time.Time `json:"at"`
	Username string    `json:"username"`
	UserID   string    `json:"userId,omitempty"`
	// Outcome: "accepted" or "rejected".
	Outcome string `json:"outcome"`
	// Reason for a refusal: outage_closed, outage_no_code, outage_unknown_user,
	// outage_cache_expired, outage_code_used, outage_locked, bad_passcode.
	Reason string `json:"reason,omitempty"`
	// Factor: "outage_code", "password_only" or "none".
	Factor string        `json:"factor"`
	Step   int64         `json:"step,omitempty"`
	NAS    RadiusNAS     `json:"nas"`
	Client RadiusEndUser `json:"client"`
}

// RadiusOutageLogResult says what Touchque wrote.
type RadiusOutageLogResult struct {
	Written    int `json:"written"`
	Duplicates int `json:"duplicates"`
	// Skipped: malformed, or older than 7 days.
	Skipped int `json:"skipped"`
}

// OutageLog sends up to 200 decisions made during an outage.
func (r *RadiusClient) OutageLog(ctx context.Context, events []RadiusOutageEvent) (*RadiusOutageLogResult, error) {
	var out RadiusOutageLogResult
	if err := r.call(ctx, "/sso/radius/v1/outage-log", map[string]interface{}{"events": events}, &out); err != nil {
		return nil, err
	}
	return &out, nil
}
