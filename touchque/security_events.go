package touchque

// Shared Signals (OpenID Shared Signals Framework 1.0): Security Event Tokens
// (SETs, RFC 8417) an identity provider sends when something happens to a
// person's account after sign-in: CAEP session-revoked, credential-change,
// device-compliance-change; RISC account-disabled, credential-compromise.
// Touchque SSO sends them for an organization's members to the receivers its
// admin adds (Organization > Continuous access). Your app ends the person's
// sessions or asks them to sign in again.
//
// Push delivery (RFC 8935), the SET is the request body (application/secevent+jwt):
//
//	v, _ := touchque.NewSecurityEventVerifier(touchque.SecurityEventVerifierConfig{Issuer: "https://sso.touchque.com", Audience: "https://app.example.com"})
//	http.HandleFunc("/ssf", func(w http.ResponseWriter, r *http.Request) {
//		body, _ := io.ReadAll(io.LimitReader(r.Body, 32<<10))
//		event, err := v.Verify(r.Context(), string(body))
//		var se *touchque.SecurityEventError
//		if errors.As(err, &se) {
//			w.WriteHeader(400)
//			json.NewEncoder(w).Encode(map[string]string{"err": se.Code, "description": se.Message})
//			return
//		}
//		if event.Name == "session-revoked" { endSessionsOf(event.Subject["email"]) }
//		w.WriteHeader(202)
//	})
//
// Poll delivery (RFC 8936): touchque.PollSecurityEvents(ctx, touchque.PollSecurityEventsParams{URL: ..., Token: ..., Ack: ...}).
//
// A SET does not expire: it says what happened. Keep the jtis you handled
// and skip a repeat.

import (
	"bytes"
	"context"
	"crypto"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"
)

// SecurityEventTypes are the event types Touchque sends, by their short name.
var SecurityEventTypes = map[string]string{
	"session-revoked":          "https://schemas.openid.net/secevent/caep/event-type/session-revoked",
	"credential-change":        "https://schemas.openid.net/secevent/caep/event-type/credential-change",
	"device-compliance-change": "https://schemas.openid.net/secevent/caep/event-type/device-compliance-change",
	"account-disabled":         "https://schemas.openid.net/secevent/risc/event-type/account-disabled",
	"credential-compromise":    "https://schemas.openid.net/secevent/risc/event-type/credential-compromise",
	"verification":             "https://schemas.openid.net/secevent/ssf/event-type/verification",
	"stream-updated":           "https://schemas.openid.net/secevent/ssf/event-type/stream-updated",
}

var setNamespace = regexp.MustCompile(`^https://schemas\.openid\.net/secevent/(caep|risc|ssf)/event-type/([a-z0-9-]+)$`)

// SecurityEventError is a refused SET. Code is the RFC 8935 error to answer
// with (HTTP 400 {"err": Code}): invalid_request, invalid_key,
// invalid_issuer or invalid_audience; temporarily_unavailable when the
// issuer's keys could not be read (answer 503: the transmitter tries again).
type SecurityEventError struct {
	Code    string
	Message string
}

func (e *SecurityEventError) Error() string {
	return fmt.Sprintf("touchque: %s (%s)", e.Message, e.Code)
}

// SecurityEvent is a verified SET.
type SecurityEvent struct {
	JTI      string
	Issuer   string
	Audience []string
	// IssuedAt is seconds since the epoch.
	IssuedAt int64
	// TXN carries the case code of Touchque's decision ("Why?" in the dashboard); empty when none.
	TXN string
	// Subject is sub_id as sent: {"format": "email", "email": ...} for a person.
	Subject map[string]interface{}
	// Type is the event type URI.
	Type string
	// Name is its short name (session-revoked …) for CAEP, RISC and SSF types; empty for others.
	Name string
	// Claims are the event's own (event_timestamp, reason_admin, credential_type …).
	Claims map[string]interface{}
}

// SecurityEventVerifierConfig configures a SecurityEventVerifier.
type SecurityEventVerifierConfig struct {
	// Issuer is the transmitter's issuer, e.g. https://sso.touchque.com.
	Issuer string
	// Audience is your stream's audience (aud), as the dashboard shows it.
	Audience string
	// JWKSURI, when not found from the issuer's /.well-known/ssf-configuration.
	JWKSURI string
	// JWKS fixes the keys instead (tests, or keys you pin): {"keys": [...]}.
	JWKS map[string]interface{}
	// ClockSkew allowed for iat (default 300 s).
	ClockSkew  time.Duration
	HTTPClient *http.Client
}

// SecurityEventVerifier checks SETs: signature (RS256, the issuer's keys), typ, issuer, audience, one event.
type SecurityEventVerifier struct {
	cfg     SecurityEventVerifierConfig
	jwksURI string
	mu      sync.Mutex
	keys    map[string]crypto.PublicKey
	keysAt  time.Time
	triedAt time.Time
}

// NewSecurityEventVerifier returns a verifier for one transmitter and audience.
func NewSecurityEventVerifier(cfg SecurityEventVerifierConfig) (*SecurityEventVerifier, error) {
	if cfg.Issuer == "" || cfg.Audience == "" {
		return nil, errors.New("touchque: SecurityEventVerifier needs Issuer (the transmitter) and Audience (your stream's aud)")
	}
	if cfg.ClockSkew == 0 {
		cfg.ClockSkew = 300 * time.Second
	}
	if cfg.HTTPClient == nil {
		cfg.HTTPClient = &http.Client{Timeout: 5 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	}
	v := &SecurityEventVerifier{cfg: cfg, jwksURI: cfg.JWKSURI}
	if cfg.JWKS != nil {
		v.setKeys(cfg.JWKS)
	}
	return v, nil
}

func (v *SecurityEventVerifier) setKeys(jwks map[string]interface{}) {
	keys := map[string]crypto.PublicKey{}
	list, _ := jwks["keys"].([]interface{})
	for _, raw := range list {
		k, _ := raw.(map[string]interface{})
		kid, _ := k["kid"].(string)
		if pub, err := mcpPublicKey(k); err == nil && kid != "" {
			keys[kid] = pub
		}
	}
	v.keys = keys
	v.keysAt = time.Now()
}

func (v *SecurityEventVerifier) loadKeys(ctx context.Context) error {
	if v.jwksURI == "" {
		meta, err := xaaGetJSON(ctx, v.cfg.HTTPClient, strings.TrimRight(v.cfg.Issuer, "/")+"/.well-known/ssf-configuration")
		if err != nil {
			return err
		}
		uri, _ := meta["jwks_uri"].(string)
		if meta["issuer"] != v.cfg.Issuer || uri == "" {
			return errors.New("the transmitter's metadata does not match its issuer")
		}
		v.jwksURI = uri
	}
	if !xaaSafeURL(v.jwksURI) {
		return fmt.Errorf("%s must be an https URL", v.jwksURI)
	}
	jwks, err := xaaGetJSON(ctx, v.cfg.HTTPClient, v.jwksURI)
	if err != nil {
		return err
	}
	v.setKeys(jwks)
	return nil
}

func (v *SecurityEventVerifier) keyFor(ctx context.Context, kid string) (crypto.PublicKey, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.cfg.JWKS != nil {
		return v.keys[kid], nil
	}
	if v.keysAt.IsZero() || time.Since(v.keysAt) > time.Hour {
		if err := v.loadKeys(ctx); err != nil {
			return nil, err
		}
	}
	if _, ok := v.keys[kid]; !ok && time.Since(v.triedAt) > 5*time.Minute {
		v.triedAt = time.Now()
		if err := v.loadKeys(ctx); err != nil {
			return nil, err
		}
	}
	return v.keys[kid], nil
}

// Verify checks a SET: the event, or *SecurityEventError.
func (v *SecurityEventVerifier) Verify(ctx context.Context, token string) (*SecurityEvent, error) {
	bad := func(m string) error { return &SecurityEventError{Code: "invalid_request", Message: m} }
	parts := strings.Split(strings.TrimSpace(token), ".")
	if len(parts) != 3 {
		return nil, bad("not a JWT")
	}
	head, err1 := mcpJSONPart(parts[0])
	c, err2 := mcpJSONPart(parts[1])
	if err1 != nil || err2 != nil {
		return nil, bad("not a JWT")
	}
	if typ, _ := head["typ"].(string); strings.ToLower(typ) != "secevent+jwt" {
		return nil, bad("not a Security Event Token (typ secevent+jwt)")
	}
	alg, _ := head["alg"].(string)
	kid, _ := head["kid"].(string)
	if alg != "RS256" || kid == "" {
		return nil, &SecurityEventError{Code: "invalid_key", Message: "unsupported signature"}
	}
	key, err := v.keyFor(ctx, kid)
	if err != nil {
		return nil, &SecurityEventError{Code: "temporarily_unavailable", Message: "the transmitter's keys could not be read: " + err.Error()}
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if key == nil || err != nil || !mcpVerifySignature(parts[0]+"."+parts[1], sig, "RS256", key) {
		return nil, &SecurityEventError{Code: "invalid_key", Message: "signature does not verify"}
	}
	if c["iss"] != v.cfg.Issuer {
		return nil, &SecurityEventError{Code: "invalid_issuer", Message: "another issuer"}
	}
	var audience []string
	if list, ok := c["aud"].([]interface{}); ok {
		for _, a := range list {
			if s, ok := a.(string); ok {
				audience = append(audience, s)
			}
		}
	} else if s, ok := c["aud"].(string); ok {
		audience = []string{s}
	}
	found := false
	for _, a := range audience {
		found = found || a == v.cfg.Audience
	}
	if !found {
		return nil, &SecurityEventError{Code: "invalid_audience", Message: "not for this receiver"}
	}
	jti, _ := c["jti"].(string)
	iat, ok := c["iat"].(float64)
	if jti == "" || !ok || iat != math.Trunc(iat) {
		return nil, bad("jti and iat are required")
	}
	if int64(iat)-int64(v.cfg.ClockSkew/time.Second) > time.Now().Unix() {
		return nil, bad("issued in the future")
	}
	events, _ := c["events"].(map[string]interface{})
	if len(events) != 1 {
		return nil, bad("a SET carries exactly one event")
	}
	out := &SecurityEvent{JTI: jti, Issuer: v.cfg.Issuer, Audience: audience, IssuedAt: int64(iat), Subject: map[string]interface{}{}, Claims: map[string]interface{}{}}
	out.TXN, _ = c["txn"].(string)
	if sub, ok := c["sub_id"].(map[string]interface{}); ok {
		out.Subject = sub
	}
	for t, claims := range events {
		out.Type = t
		if m := setNamespace.FindStringSubmatch(t); m != nil {
			out.Name = m[2]
		}
		if cl, ok := claims.(map[string]interface{}); ok {
			out.Claims = cl
		}
	}
	return out, nil
}

// PollSecurityEventsParams is one poll (RFC 8936).
type PollSecurityEventsParams struct {
	// URL is the stream's poll endpoint (its delivery.endpoint_url).
	URL string
	// Token is the stream's token.
	Token string
	// Ack lists the jtis you handled since the last poll.
	Ack []string
	// SetErrs are the jtis you could not handle: {jti: {"err": ..., "description": ...}}.
	SetErrs           map[string]map[string]string
	MaxEvents         *int
	ReturnImmediately *bool
	HTTPClient        *http.Client
}

// PollSecurityEventsResult holds the waiting SETs (jti → token).
type PollSecurityEventsResult struct {
	Sets          map[string]string `json:"sets"`
	MoreAvailable bool              `json:"moreAvailable"`
}

// PollSecurityEvents acknowledges what you handled and returns the waiting SETs.
func PollSecurityEvents(ctx context.Context, p PollSecurityEventsParams) (*PollSecurityEventsResult, error) {
	if !xaaSafeURL(p.URL) {
		return nil, fmt.Errorf("touchque: %s must be an https URL", p.URL)
	}
	if p.Token == "" {
		return nil, errors.New("touchque: PollSecurityEvents needs the stream's token")
	}
	body := map[string]interface{}{}
	if p.Ack != nil {
		body["ack"] = p.Ack
	}
	if p.SetErrs != nil {
		body["setErrs"] = p.SetErrs
	}
	if p.MaxEvents != nil {
		body["maxEvents"] = *p.MaxEvents
	}
	if p.ReturnImmediately != nil {
		body["returnImmediately"] = *p.ReturnImmediately
	}
	raw, _ := json.Marshal(body)
	req, err := http.NewRequestWithContext(ctx, "POST", p.URL, bytes.NewReader(raw))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", "Bearer "+p.Token)
	client := p.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: 30 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	out := &PollSecurityEventsResult{Sets: map[string]string{}}
	if resp.StatusCode != 200 {
		var e struct {
			Error string `json:"error"`
		}
		_ = json.NewDecoder(resp.Body).Decode(&e)
		if e.Error == "" {
			e.Error = "server_error"
		}
		return nil, &SecurityEventError{Code: e.Error, Message: fmt.Sprintf("%s answered %d", p.URL, resp.StatusCode)}
	}
	if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
		return nil, err
	}
	if out.Sets == nil {
		out.Sets = map[string]string{}
	}
	return out, nil
}
