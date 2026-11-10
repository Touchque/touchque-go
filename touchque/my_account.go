package touchque

// The TouchQue Login My Account API (/me/v1) from your server: the signed-in
// customer's own profile, sign-in methods, devices, apps and data, called
// with their access token for audience https://<domain>/me/.
//
//	me, _ := login.MyAccountToken(ctx, refreshToken, "read:me update:me") // keep me.RefreshToken
//	account := login.MyAccount(me.AccessToken)
//	out, _ := account.Get(ctx)
//
// Security changes, the data export and deletion need a recent sign-in; when
// it is too old the error is a *MyAccountError with StepUp() true: send the
// person through AuthorizationURL with MaxAge -1 (max_age=0) again, and pass
// MaxAge -1 in the CallbackChecks too.

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
)

// MyAccountError is a failed My Account API call.
type MyAccountError struct {
	Code        string
	Description string
	Status      int
	// MaxAge is the sign-in age (seconds) the call needs, on a step-up answer.
	MaxAge int
}

func (e *MyAccountError) Error() string {
	if e.Description != "" {
		return e.Code + ": " + e.Description
	}
	return e.Code
}

// StepUp is true when the sign-in is too old for this change (RFC 9470).
func (e *MyAccountError) StepUp() bool { return e.Code == "insufficient_user_authentication" }

// MyAccount calls /me/v1 for one person.
type MyAccount struct {
	Issuer string
	token  string
	http   *http.Client
}

// NewMyAccount makes a client for the person holding accessToken (audience https://<domain>/me/).
func NewMyAccount(domain, accessToken string, client *http.Client) *MyAccount {
	issuer := strings.TrimRight(domain, "/")
	if !strings.HasPrefix(issuer, "http://") && !strings.HasPrefix(issuer, "https://") {
		issuer = "https://" + issuer
	}
	if client == nil {
		client = http.DefaultClient
	}
	return &MyAccount{Issuer: issuer, token: accessToken, http: client}
}

// MyAccountToken trades the refresh token a first-party app holds for a My
// Account API token. The refresh token rotates: keep the returned one.
// Scopes: read:me, update:me, manage:me:security, delete:me.
func (l *HostedLogin) MyAccountToken(ctx context.Context, refreshToken, scope string) (*TokenSet, error) {
	if scope == "" {
		scope = "read:me update:me"
	}
	return l.token(ctx, url.Values{"grant_type": {"refresh_token"}, "refresh_token": {refreshToken}, "audience": {l.Issuer + "/me/"}, "scope": {scope}})
}

// MyAccount is the My Account API for the person holding accessToken.
func (l *HostedLogin) MyAccount(accessToken string) *MyAccount {
	return NewMyAccount(l.Issuer, accessToken, l.http)
}

// AccountURL is the hosted account page; section is "", "security", "devices" or "privacy".
func (l *HostedLogin) AccountURL(section string) string {
	if section == "" {
		return l.Issuer + "/account"
	}
	return l.Issuer + "/account/" + section
}

// AccountPageURL is the hosted account page; section is "", "security", "devices" or "privacy".
func (m *MyAccount) AccountPageURL(section string) string {
	if section == "" {
		return m.Issuer + "/account"
	}
	return m.Issuer + "/account/" + section
}

var maxAgeRE = regexp.MustCompile(`max_age="?(\d+)"?`)

func (m *MyAccount) call(ctx context.Context, method, path string, in interface{}) (map[string]interface{}, error) {
	var body io.Reader
	if in != nil {
		raw, err := json.Marshal(in)
		if err != nil {
			return nil, err
		}
		body = bytes.NewReader(raw)
	}
	req, err := http.NewRequestWithContext(ctx, method, m.Issuer+"/me/v1"+path, body)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+m.token)
	req.Header.Set("Accept", "application/json")
	if in != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	res, err := m.http.Do(req)
	if err != nil {
		return nil, &NetworkError{Message: err.Error()}
	}
	defer res.Body.Close()
	if res.StatusCode == http.StatusNoContent {
		return nil, nil
	}
	raw, _ := io.ReadAll(io.LimitReader(res.Body, 8<<20))
	var out map[string]interface{}
	_ = json.Unmarshal(raw, &out)
	if res.StatusCode >= 400 {
		e := &MyAccountError{Code: fmt.Sprintf("http_%d", res.StatusCode), Status: res.StatusCode}
		if s, ok := out["error"].(string); ok && s != "" {
			e.Code = s
		}
		if s, ok := out["error_description"].(string); ok {
			e.Description = s
		}
		if match := maxAgeRE.FindStringSubmatch(res.Header.Get("WWW-Authenticate")); match != nil {
			e.MaxAge, _ = strconv.Atoi(match[1])
		}
		return nil, e
	}
	return out, nil
}

// Get returns the profile, the sign-in methods and the account page URL.
func (m *MyAccount) Get(ctx context.Context) (map[string]interface{}, error) {
	return m.call(ctx, http.MethodGet, "", nil)
}

func (m *MyAccount) GetProfile(ctx context.Context) (map[string]interface{}, error) {
	return m.call(ctx, http.MethodGet, "/profile", nil)
}

// UpdateProfile changes name, givenName, familyName, nickname, locale;
// userMetadata is merged and a key set to nil is removed.
func (m *MyAccount) UpdateProfile(ctx context.Context, changes map[string]interface{}) (map[string]interface{}, error) {
	return m.call(ctx, http.MethodPatch, "/profile", changes)
}

func (m *MyAccount) AuthenticationMethods(ctx context.Context) (map[string]interface{}, error) {
	return m.call(ctx, http.MethodGet, "/authentication-methods", nil)
}

func (m *MyAccount) RenamePasskey(ctx context.Context, id, label string) error {
	_, err := m.call(ctx, http.MethodPatch, "/authentication-methods/passkeys/"+idSeg(id), map[string]string{"label": label})
	return err
}

// RemovePasskey needs a recent sign-in.
func (m *MyAccount) RemovePasskey(ctx context.Context, id string) error {
	_, err := m.call(ctx, http.MethodDelete, "/authentication-methods/passkeys/"+idSeg(id), nil)
	return err
}

// UnlinkTouchQueApp needs a recent sign-in.
func (m *MyAccount) UnlinkTouchQueApp(ctx context.Context) error {
	_, err := m.call(ctx, http.MethodDelete, "/authentication-methods/touchque", nil)
	return err
}

// SetEmailCodes turns email codes as a second step on or off. Needs a recent sign-in.
func (m *MyAccount) SetEmailCodes(ctx context.Context, enabled bool) error {
	_, err := m.call(ctx, http.MethodPut, "/authentication-methods/email", map[string]bool{"enabled": enabled})
	return err
}

// StartSMSEnrollment texts a code to a new number for text-message codes. Needs a recent sign-in.
func (m *MyAccount) StartSMSEnrollment(ctx context.Context, phone string) (map[string]interface{}, error) {
	return m.call(ctx, http.MethodPost, "/authentication-methods/sms", map[string]string{"phone": phone})
}

// VerifySMSEnrollment checks the code from that text; text-message codes are then on. Needs a recent sign-in.
func (m *MyAccount) VerifySMSEnrollment(ctx context.Context, code string) (map[string]interface{}, error) {
	return m.call(ctx, http.MethodPost, "/authentication-methods/sms/verify", map[string]string{"code": code})
}

// RemoveSMSCodes needs a recent sign-in.
func (m *MyAccount) RemoveSMSCodes(ctx context.Context) error {
	_, err := m.call(ctx, http.MethodDelete, "/authentication-methods/sms", nil)
	return err
}

// UnlinkIdentity disconnects a linked account. Needs a recent sign-in.
func (m *MyAccount) UnlinkIdentity(ctx context.Context, id string) error {
	_, err := m.call(ctx, http.MethodDelete, "/identities/"+idSeg(id), nil)
	return err
}

// StopAppAccess makes apps stop using a linked account for the person (token
// vault: the identity's appAccess id); signing in with it stays.
func (m *MyAccount) StopAppAccess(ctx context.Context, id string) error {
	_, err := m.call(ctx, http.MethodDelete, "/app-access/"+idSeg(id), nil)
	return err
}

// SetPassword sets or changes the password; other sessions end. Needs a recent sign-in.
func (m *MyAccount) SetPassword(ctx context.Context, password string) (map[string]interface{}, error) {
	return m.call(ctx, http.MethodPut, "/password", map[string]string{"password": password})
}

// RemovePassword needs a recent sign-in and another way to sign in.
func (m *MyAccount) RemovePassword(ctx context.Context) error {
	_, err := m.call(ctx, http.MethodDelete, "/password", nil)
	return err
}

// ChangeEmail sends a confirmation link to the new address. Needs a recent sign-in.
func (m *MyAccount) ChangeEmail(ctx context.Context, email string) (map[string]interface{}, error) {
	return m.call(ctx, http.MethodPost, "/email", map[string]string{"email": email})
}

func (m *MyAccount) SendVerificationEmail(ctx context.Context) error {
	_, err := m.call(ctx, http.MethodPost, "/email/verification", nil)
	return err
}

func (m *MyAccount) Sessions(ctx context.Context) (map[string]interface{}, error) {
	return m.call(ctx, http.MethodGet, "/sessions", nil)
}

func (m *MyAccount) EndSession(ctx context.Context, id string) error {
	_, err := m.call(ctx, http.MethodDelete, "/sessions/"+idSeg(id), nil)
	return err
}

// EndOtherSessions signs out every other device.
func (m *MyAccount) EndOtherSessions(ctx context.Context) (map[string]interface{}, error) {
	return m.call(ctx, http.MethodDelete, "/sessions", nil)
}

func (m *MyAccount) Apps(ctx context.Context) (map[string]interface{}, error) {
	return m.call(ctx, http.MethodGet, "/apps", nil)
}

func (m *MyAccount) RevokeApp(ctx context.Context, clientID string) (map[string]interface{}, error) {
	return m.call(ctx, http.MethodDelete, "/apps/"+idSeg(clientID), nil)
}

func (m *MyAccount) Consents(ctx context.Context) (map[string]interface{}, error) {
	return m.call(ctx, http.MethodGet, "/consents", nil)
}

func (m *MyAccount) SetMarketing(ctx context.Context, granted bool) error {
	_, err := m.call(ctx, http.MethodPut, "/consents/marketing", map[string]bool{"granted": granted})
	return err
}

// ExportData returns everything about the person (KVKK/GDPR). Needs a recent sign-in.
func (m *MyAccount) ExportData(ctx context.Context) (map[string]interface{}, error) {
	return m.call(ctx, http.MethodGet, "/export", nil)
}

// DeleteAccount erases the account at once. Needs delete:me and a recent sign-in.
func (m *MyAccount) DeleteAccount(ctx context.Context) (map[string]interface{}, error) {
	return m.call(ctx, http.MethodDelete, "", nil)
}
