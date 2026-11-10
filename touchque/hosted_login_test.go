package touchque

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

type fakeTenant struct {
	key, signWith  *rsa.PrivateKey
	codes          map[string][2]string
	nonceOverride  string
	srv            *httptest.Server
	lastAuthHeader string
	tokenCalls     int
}

func signJWT(t *testing.T, key *rsa.PrivateKey, typ string, payload map[string]interface{}) string {
	h, _ := json.Marshal(map[string]string{"alg": "RS256", "typ": typ, "kid": "k1"})
	p, _ := json.Marshal(payload)
	input := b64u(h) + "." + b64u(p)
	sum := sha256.Sum256([]byte(input))
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, sum[:])
	if err != nil {
		t.Fatal(err)
	}
	return input + "." + b64u(sig)
}

func newFakeTenant(t *testing.T) *fakeTenant {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	f := &fakeTenant{key: key, signWith: key, codes: map[string][2]string{}}
	f.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/.well-known/jwks.json":
			json.NewEncoder(w).Encode(map[string]interface{}{"keys": []map[string]string{{"kty": "RSA", "kid": "k1", "use": "sig", "n": b64u(key.N.Bytes()), "e": b64u(big.NewInt(int64(key.E)).Bytes())}}})
		case "/oauth/token":
			r.ParseForm()
			f.lastAuthHeader = r.Header.Get("Authorization")
			f.tokenCalls++
			now := time.Now().Unix()
			iss := f.srv.URL
			if r.Form.Get("grant_type") == "authorization_code" {
				c, ok := f.codes[r.Form.Get("code")]
				sum := sha256.Sum256([]byte(r.Form.Get("code_verifier")))
				if !ok || c[0] != b64u(sum[:]) {
					w.WriteHeader(400)
					w.Write([]byte(`{"error":"invalid_grant"}`))
					return
				}
				at := signJWT(t, key, "at+jwt", map[string]interface{}{"iss": iss, "sub": "usr_1", "aud": []string{"https://api.acme.test"}, "exp": now + 300, "iat": now, "client_id": "client-123", "scope": "openid read:orders"})
				atSum := sha256.Sum256([]byte(at))
				nonce := c[1]
				if f.nonceOverride != "" {
					nonce = f.nonceOverride
				}
				id := signJWT(t, f.signWith, "JWT", map[string]interface{}{"iss": iss, "sub": "usr_1", "aud": "client-123", "exp": now + 300, "iat": now, "nonce": nonce, "email": "a@acme.test", "at_hash": b64u(atSum[:16])})
				json.NewEncoder(w).Encode(map[string]interface{}{"access_token": at, "token_type": "Bearer", "expires_in": 300, "scope": "openid", "id_token": id, "refresh_token": "tqr_1"})
				return
			}
			json.NewEncoder(w).Encode(map[string]interface{}{"access_token": "x", "token_type": "Bearer", "expires_in": 300, "refresh_token": "tqr_2"})
		default:
			w.WriteHeader(404)
		}
	}))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeTenant) authorize(raw string) url.Values {
	u, _ := url.Parse(raw)
	q := u.Query()
	code := "code-" + string(rune('a'+len(f.codes)))
	f.codes[code] = [2]string{q.Get("code_challenge"), q.Get("nonce")}
	return url.Values{"code": {code}, "state": {q.Get("state")}}
}

func TestHostedLoginFlow(t *testing.T) {
	f := newFakeTenant(t)
	ctx := context.Background()
	login, err := NewHostedLogin(HostedLoginConfig{Domain: f.srv.URL, ClientID: "client-123", ClientSecret: "s3cret", RedirectURI: "https://app/cb", Audience: "https://api.acme.test"})
	if err != nil {
		t.Fatal(err)
	}
	req, _ := login.AuthorizationURL(AuthorizationOptions{ScreenHint: "signup"})
	u, _ := url.Parse(req.URL)
	sum := sha256.Sum256([]byte(req.CodeVerifier))
	if u.Query().Get("code_challenge") != b64u(sum[:]) || u.Query().Get("code_challenge_method") != "S256" || u.Query().Get("screen_hint") != "signup" || u.Query().Get("audience") != "https://api.acme.test" {
		t.Fatalf("bad authorize URL %s", req.URL)
	}
	params := f.authorize(req.URL)
	params.Set("iss", f.srv.URL)
	tokens, err := login.HandleCallback(ctx, params, CallbackChecks{State: req.State, Nonce: req.Nonce, CodeVerifier: req.CodeVerifier})
	if err != nil {
		t.Fatal(err)
	}
	if tokens.Claims["sub"] != "usr_1" || tokens.RefreshToken != "tqr_1" || !strings.HasPrefix(f.lastAuthHeader, "Basic ") {
		t.Fatalf("unexpected tokens %+v", tokens)
	}
	if _, err := login.VerifyAccessToken(ctx, tokens.AccessToken, "https://api.acme.test", "read:orders"); err != nil {
		t.Fatal(err)
	}
	var le *HostedLoginError
	if _, err := login.VerifyAccessToken(ctx, tokens.AccessToken, "https://api.acme.test", "write:orders"); !errors.As(err, &le) || le.Code != "insufficient_scope" {
		t.Fatalf("want insufficient_scope, got %v", err)
	}
	if _, err := login.VerifyAccessToken(ctx, tokens.IDToken, "client-123"); err == nil {
		t.Fatal("an ID token is not an access token")
	}
	next, err := login.Refresh(ctx, "tqr_1")
	if err != nil || next.RefreshToken != "tqr_2" {
		t.Fatalf("refresh: %v %+v", err, next)
	}
}

func TestHostedLoginRefusals(t *testing.T) {
	f := newFakeTenant(t)
	ctx := context.Background()
	login, _ := NewHostedLogin(HostedLoginConfig{Domain: f.srv.URL, ClientID: "client-123", RedirectURI: "https://app/cb"})
	req, _ := login.AuthorizationURL(AuthorizationOptions{})
	p := f.authorize(req.URL)
	checks := CallbackChecks{State: req.State, Nonce: req.Nonce, CodeVerifier: req.CodeVerifier}
	cases := map[string]url.Values{
		"state_mismatch":  {"code": {p.Get("code")}, "state": {"other"}},
		"access_denied":   {"error": {"access_denied"}, "state": {req.State}},
		"issuer_mismatch": {"code": {p.Get("code")}, "state": {req.State}, "iss": {"https://evil"}},
	}
	for want, params := range cases {
		var le *HostedLoginError
		if _, err := login.HandleCallback(ctx, params, checks); !errors.As(err, &le) || le.Code != want {
			t.Fatalf("want %s, got %v", want, err)
		}
	}
	f.nonceOverride = "replayed"
	req2, _ := login.AuthorizationURL(AuthorizationOptions{})
	var le *HostedLoginError
	if _, err := login.HandleCallback(ctx, f.authorize(req2.URL), CallbackChecks{State: req2.State, Nonce: req2.Nonce, CodeVerifier: req2.CodeVerifier}); !errors.As(err, &le) || le.Code != "nonce_mismatch" {
		t.Fatalf("want nonce_mismatch, got %v", err)
	}
	f.nonceOverride = ""
	other, _ := rsa.GenerateKey(rand.Reader, 2048)
	f.signWith = other
	req3, _ := login.AuthorizationURL(AuthorizationOptions{})
	if _, err := login.HandleCallback(ctx, f.authorize(req3.URL), CallbackChecks{State: req3.State, Nonce: req3.Nonce, CodeVerifier: req3.CodeVerifier}); err == nil || !strings.Contains(err.Error(), "signature") {
		t.Fatalf("want a bad signature, got %v", err)
	}

}

func TestHostedLoginChecksIss(t *testing.T) {
	// RFC 9207: this issuer or none is accepted, a foreign or empty one is refused before the code exchange.
	f := newFakeTenant(t)
	ctx := context.Background()
	login, _ := NewHostedLogin(HostedLoginConfig{Domain: f.srv.URL, ClientID: "client-123", RedirectURI: "https://app/cb"})
	req, _ := login.AuthorizationURL(AuthorizationOptions{})
	p := f.authorize(req.URL)
	checks := CallbackChecks{State: req.State, Nonce: req.Nonce, CodeVerifier: req.CodeVerifier}
	refused := []url.Values{
		{"code": {p.Get("code")}, "state": {req.State}, "iss": {"https://evil"}},
		{"code": {p.Get("code")}, "state": {req.State}, "iss": {f.srv.URL + ".evil"}},
		{"code": {p.Get("code")}, "state": {req.State}, "iss": {f.srv.URL + "/"}},
		{"code": {p.Get("code")}, "state": {req.State}, "iss": {""}},
		// A foreign error answer is reported as the issuer mismatch, not as its own error.
		{"error": {"access_denied"}, "state": {req.State}, "iss": {"https://evil"}},
	}
	empty, _ := url.ParseQuery("code=" + p.Get("code") + "&state=" + req.State + "&iss=")
	refused = append(refused, empty)
	for _, params := range refused {
		var le *HostedLoginError
		if _, err := login.HandleCallback(ctx, params, checks); !errors.As(err, &le) || le.Code != "issuer_mismatch" {
			t.Fatalf("iss %q: want issuer_mismatch, got %v", params.Get("iss"), err)
		}
	}
	if f.tokenCalls != 0 {
		t.Fatalf("a refused iss reached the token endpoint %d times", f.tokenCalls)
	}
	matching := url.Values{"code": {p.Get("code")}, "state": {req.State}, "iss": {f.srv.URL}}
	if tokens, err := login.HandleCallback(ctx, matching, checks); err != nil || tokens.Claims["sub"] != "usr_1" {
		t.Fatalf("this issuer: %v", err)
	}
	req2, _ := login.AuthorizationURL(AuthorizationOptions{})
	if tokens, err := login.HandleCallback(ctx, f.authorize(req2.URL), CallbackChecks{State: req2.State, Nonce: req2.Nonce, CodeVerifier: req2.CodeVerifier}); err != nil || tokens.Claims["sub"] != "usr_1" {
		t.Fatalf("no iss (an older server): %v", err)
	}
}

func TestHostedLoginActsForAUser(t *testing.T) {
	var forms []url.Values
	polls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		forms = append(forms, r.PostForm)
		w.Header().Set("Content-Type", "application/json")
		reply := func(status int, v interface{}) { w.WriteHeader(status); _ = json.NewEncoder(w).Encode(v) }
		switch {
		case r.URL.Path == "/bc-authorize":
			reply(200, map[string]interface{}{"auth_req_id": "req-1", "expires_in": 300, "interval": 0, "binding_code": "42"})
		case r.PostForm.Get("requested_token_type") == ConnectionTokenType:
			reply(200, map[string]interface{}{"access_token": "ya29.g", "token_type": "Bearer", "expires_in": 3500, "scope": "openid email", "connection": r.PostForm.Get("connection")})
		case r.PostForm.Get("grant_type") == "urn:ietf:params:oauth:grant-type:token-exchange":
			reply(200, map[string]interface{}{"access_token": "at-x", "token_type": "Bearer", "expires_in": 120, "issued_token_type": "urn:ietf:params:oauth:token-type:access_token"})
		default:
			polls++
			if polls == 1 {
				reply(400, map[string]string{"error": "authorization_pending"})
			} else if r.PostForm.Get("auth_req_id") == "denied" {
				reply(400, map[string]string{"error": "access_denied"})
			} else {
				reply(200, map[string]interface{}{"access_token": "at-c", "token_type": "Bearer", "expires_in": 300, "authorization_details": []map[string]string{{"type": "payment_initiation"}}})
			}
		}
	}))
	defer srv.Close()
	login, err := NewHostedLogin(HostedLoginConfig{Domain: srv.URL, ClientID: "client-123", ClientSecret: "s3cret"})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	ex, err := login.ExchangeToken(ctx, "user-at", "https://api.acme.test", "payments:create")
	if err != nil || ex.AccessToken != "at-x" || ex.IssuedTokenType == "" || forms[0].Get("subject_token") != "user-at" {
		t.Fatal(ex, err)
	}
	ask, err := login.AskUser(ctx, AskUserParams{LoginHint: "ada@acme.test", Scope: "openid payments:create", BindingMessage: "Pay invoice 42", AuthorizationDetails: []map[string]interface{}{{"type": "payment_initiation"}}})
	if err != nil || ask.AuthReqID != "req-1" || ask.BindingCode != "42" {
		t.Fatal(ask, err)
	}
	approved, err := login.WaitForUser(ctx, ask)
	if err != nil || approved.AccessToken != "at-c" || approved.AuthorizationDetails[0]["type"] != "payment_initiation" {
		t.Fatal(approved, err)
	}
	polls = 0
	ask.AuthReqID = "denied"
	var e *HostedLoginError
	if _, err := login.WaitForUser(ctx, ask); !errors.As(err, &e) || e.Code != "access_denied" {
		t.Fatal(err)
	}
	vaulted, err := login.GetConnectionToken(ctx, "user-at", "google", "email")
	last := forms[len(forms)-1]
	if err != nil || vaulted.AccessToken != "ya29.g" || vaulted.Connection != "google" || last.Get("audience") != "" || last.Get("scope") != "email" {
		t.Fatal(vaulted, err)
	}
}

func TestHostedLoginStepUpSendsMaxAgeZero(t *testing.T) {
	f := newFakeTenant(t)
	ctx := context.Background()
	login, _ := NewHostedLogin(HostedLoginConfig{Domain: f.srv.URL, ClientID: "client-123", RedirectURI: "https://app/cb"})
	for maxAge, want := range map[int]string{0: "", 600: "600", -1: "0"} {
		req, _ := login.AuthorizationURL(AuthorizationOptions{MaxAge: maxAge})
		u, _ := url.Parse(req.URL)
		if got, sent := u.Query()["max_age"]; (want == "" && sent) || (want != "" && (len(got) != 1 || got[0] != want)) {
			t.Fatalf("MaxAge %d: max_age %v, want %q", maxAge, got, want)
		}
	}
	now := time.Now().Unix()
	idToken := func(authTime int64) string {
		return signJWT(t, f.key, "JWT", map[string]interface{}{"iss": f.srv.URL, "sub": "usr_1", "aud": "client-123", "exp": now + 300, "iat": now, "auth_time": authTime})
	}
	var le *HostedLoginError
	if _, err := login.VerifyIDToken(ctx, idToken(now-600), "", "", -1); !errors.As(err, &le) || le.Code != "login_required" {
		t.Fatalf("a step-up must refuse an old sign-in, got %v", err)
	}
	if _, err := login.VerifyIDToken(ctx, idToken(now), "", "", -1); err != nil {
		t.Fatalf("a sign-in just now passes a step-up: %v", err)
	}
	if _, err := login.VerifyIDToken(ctx, idToken(now-600), "", "", 0); err != nil {
		t.Fatalf("0 checks no age: %v", err)
	}
}

func TestHostedLoginRefusesAPlaintextDomain(t *testing.T) {
	for _, domain := range []string{"http://acme.login.touchque.com", "http://10.0.0.5:8080", "http://sso.example.com/tenant"} {
		var le *HostedLoginError
		if _, err := NewHostedLogin(HostedLoginConfig{Domain: domain, ClientID: "c1"}); !errors.As(err, &le) || le.Code != "config" {
			t.Fatalf("%s: want a config error, got %v", domain, err)
		}
	}
	for _, domain := range []string{"acme.login.touchque.com", "https://acme.login.touchque.com", "http://localhost:4000", "http://127.0.0.1:4000", "http://[::1]:4000", "http://acme.login.localhost:4000"} {
		if _, err := NewHostedLogin(HostedLoginConfig{Domain: domain, ClientID: "c1"}); err != nil {
			t.Fatalf("%s: %v", domain, err)
		}
	}
}
