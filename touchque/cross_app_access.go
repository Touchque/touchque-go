package touchque

// Cross App Access: Identity Assertion JWT Authorization Grants (ID-JAG,
// draft-ietf-oauth-identity-assertion-authz-grant, an open standard). An
// organization's identity provider (Touchque SSO) decides which of its apps
// may reach which other service for its members; the app trades a member's ID
// token for an ID-JAG there, then the ID-JAG for an access token at the other
// service's authorization server, with no consent screen per member.
//
// Your app, signed in with Touchque SSO (an OpenID Connect app with a secret):
//
//	jag, err := touchque.RequestIDJAG(ctx, touchque.RequestIDJAGParams{Issuer: "https://sso.touchque.com",
//		ClientID: clientID, ClientSecret: secret, IDToken: idToken, Audience: "https://auth.files.example"})
//	tokens, err := touchque.RedeemIDJAG(ctx, touchque.RedeemIDJAGParams{TokenEndpoint: "https://auth.files.example/token",
//		ClientID: "acme", ClientSecret: filesSecret, Assertion: jag.Assertion})
//
// Your own authorization server, taking ID-JAGs from an organization's identity provider; build
// the verifier once (it keeps the used jtis and the identity provider's keys):
//
//	v, _ := touchque.NewIDJAGVerifier(touchque.IDJAGVerifierConfig{Issuer: "https://sso.touchque.com", Audience: "https://auth.files.example"})
//	claims, err := v.Verify(r.Context(), r.PostFormValue("assertion"), authenticatedClientID) // per request
//
// Sender-constrained with DPoP (RFC 9449), optional: give the same key to both calls. The
// ID-JAG is then bound to it (cnf.jkt) and is useless to anyone who copies it without the key.
// A token endpoint that asks for a DPoP nonce (use_dpop_nonce, with a DPoP-Nonce header of valid
// nonce syntax) gets the request once more with it.
//
//	key, err := touchque.NewIDJAGDPoPKey()
//	jag, err := touchque.RequestIDJAG(ctx, touchque.RequestIDJAGParams{ /* as above */ DPoPKey: key}) // jag.DPoPBound
//	tokens, err := touchque.RedeemIDJAG(ctx, touchque.RedeemIDJAGParams{ /* as above */ Assertion: jag.Assertion, DPoPKey: key})
//
// When the other service's authorization server supports DPoP, the access token is DPoP-bound
// too (token_type DPoP): each call to its API sends it with a proof for that call. One without
// DPoP support issues a Bearer token, sent as Authorization: Bearer <token> with no proof.
//
//	proof, err := touchque.IDJAGDPoPProofWith(key, "GET", apiURL, touchque.IDJAGDPoPProofOptions{AccessToken: accessToken})
//	req.Header.Set("Authorization", "DPoP "+accessToken)
//	req.Header.Set("DPoP", proof)
//
// An authorization server that checks DPoP proofs passes the proof key's thumbprint; a bound
// ID-JAG without it is refused:
//
//	claims, err := v.VerifyWithDPoP(ctx, assertion, authenticatedClientID, proofJKT)

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	IDJAGTokenType     = "urn:ietf:params:oauth:token-type:id-jag"
	IDTokenTokenType   = "urn:ietf:params:oauth:token-type:id_token"
	TokenExchangeGrant = "urn:ietf:params:oauth:grant-type:token-exchange"
	JWTBearerGrant     = "urn:ietf:params:oauth:grant-type:jwt-bearer"
	idJagTyp           = "oauth-id-jag+jwt"
)

// IDJAGError is a refused ID-JAG or exchange; Code is the OAuth error
// (invalid_grant for a bad ID-JAG).
type IDJAGError struct {
	Code    string
	Message string
	Status  int
	// DPoPNonce is the latest valid DPoP-Nonce (RFC 9449 section 8) the token endpoint sent
	// during this call: from the answer to the retry when that had one, else from the first
	// answer; "" when none was of valid syntax. With a DPoPKey, a token endpoint that asked for
	// a nonce (use_dpop_nonce) already got the request once more with a valid one; this field is
	// for diagnostics, and for resource requests (a proof's nonce is IDJAGDPoPProofOptions.Nonce).
	DPoPNonce string
}

func (e *IDJAGError) Error() string { return fmt.Sprintf("touchque: %s (%s)", e.Message, e.Code) }

// IDJAGVerifierConfig configures a verifier at your authorization server.
type IDJAGVerifierConfig struct {
	// Issuer is the identity provider, e.g. https://sso.touchque.com.
	Issuer string
	// Audience is your authorization server's issuer identifier (the ID-JAG's aud).
	Audience string
	// JWKSURI, when not found from the issuer's /.well-known/openid-configuration.
	JWKSURI string
	// ClockSkew allowed (default 60 s).
	ClockSkew time.Duration
	// FirstUse records an ID-JAG's jti and says whether it is new (each is used
	// once). Defaults to memory in this process; give a shared store (Redis SET
	// NX) when several processes take ID-JAGs.
	FirstUse   func(jti string, expiresAt int64) bool
	HTTPClient *http.Client
}

// IDJAGClaims is a checked ID-JAG.
type IDJAGClaims struct {
	Iss       string
	Sub       string // the member at the identity provider
	Aud       string
	ClientID  string // your client_id of the app that presented it
	JTI       string
	IssuedAt  int64
	ExpiresAt int64
	Scopes    []string
	Resource  string
	Tenant    string
	Email     string
	AuthTime  int64
	AMR       []string
	// CnfJKT is the DPoP key thumbprint the ID-JAG is bound to (cnf.jkt), when it is.
	CnfJKT string
	Claims map[string]interface{}
}

// IDJAGDPoPKey is a DPoP key (RFC 9449, P-256) that binds an ID-JAG to its holder; keep it in
// this process. Make it with NewIDJAGDPoPKey or NewIDJAGDPoPKeyFrom. The private key is
// unexported (PrivateKey returns a copy), so encoding/json, fmt and log/slog never print it.
type IDJAGDPoPKey struct {
	// PublicJWK is the public key (kty, crv, x, y) each proof carries; proofs make it from the
	// private key, never from this map.
	PublicJWK map[string]interface{}
	// Thumbprint is the RFC 7638 thumbprint: the ID-JAG's cnf.jkt.
	Thumbprint string
	priv       *ecdsa.PrivateKey
}

// NewIDJAGDPoPKey makes a fresh DPoP key for RequestIDJAG and RedeemIDJAG.
func NewIDJAGDPoPKey() (*IDJAGDPoPKey, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	return idJagDPoPKey(priv), nil
}

// NewIDJAGDPoPKeyFrom makes a DPoP key from a P-256 private key you keep yourself, for example
// to call with the DPoP-bound access token from another process. Any other key is a
// *ConfigError.
func NewIDJAGDPoPKeyFrom(priv *ecdsa.PrivateKey) (*IDJAGDPoPKey, error) {
	bad := &ConfigError{Message: "touchque: a DPoP key must be an EC P-256 private key"}
	if priv == nil || priv.Curve != elliptic.P256() {
		return nil, bad
	}
	raw, err := ecdsaScalar(priv)
	if err != nil {
		return nil, bad
	}
	// A copy of its own, with the public half made from the scalar.
	clean, err := ecdsa.ParseRawPrivateKey(elliptic.P256(), raw)
	if err != nil {
		return nil, bad
	}
	return idJagDPoPKey(clean), nil
}

// ecdsaScalar is priv.Bytes(), with an error where crypto/ecdsa panics: a half-built key (no
// scalar or point).
func ecdsaScalar(priv *ecdsa.PrivateKey) (raw []byte, err error) {
	defer func() {
		if recover() != nil {
			raw, err = nil, errors.New("touchque: an incomplete EC private key")
		}
	}()
	return priv.Bytes()
}

func idJagDPoPKey(priv *ecdsa.PrivateKey) *IDJAGDPoPKey {
	public := ecPublicJWK(&priv.PublicKey)
	return &IDJAGDPoPKey{PublicJWK: public, Thumbprint: JWKThumbprint(public), priv: priv}
}

// PrivateKey returns a copy of the private key, to keep it yourself (NewIDJAGDPoPKeyFrom takes it
// back); nil for a key not made by NewIDJAGDPoPKey or NewIDJAGDPoPKeyFrom.
func (k *IDJAGDPoPKey) PrivateKey() *ecdsa.PrivateKey {
	if k == nil || k.priv == nil {
		return nil
	}
	raw, err := k.priv.Bytes()
	if err != nil {
		return nil
	}
	priv, _ := ecdsa.ParseRawPrivateKey(elliptic.P256(), raw)
	return priv
}

// signer signs the key's proofs; a key not made by NewIDJAGDPoPKey or NewIDJAGDPoPKeyFrom (nil,
// the zero value) is a *ConfigError.
func (k *IDJAGDPoPKey) signer() (*Agent, error) {
	if k == nil || k.priv == nil || k.priv.Curve != elliptic.P256() {
		return nil, &ConfigError{Message: "touchque: the DPoP key is empty: make it with NewIDJAGDPoPKey or NewIDJAGDPoPKeyFrom"}
	}
	return signerFor(k.priv, nil), nil
}

// IDJAGDPoPProofOptions are a DPoP proof's optional claims.
type IDJAGDPoPProofOptions struct {
	// AccessToken: a request that sends a DPoP-bound access token (Authorization: DPoP <token>)
	// carries its hash in the proof (ath).
	AccessToken string
	// Nonce: the DPoP-Nonce the server this request goes to asked for (RFC 9449 sections 8 and 9).
	Nonce string
}

// IDJAGDPoPProof is a DPoP proof for one POST to target (htu without query or fragment): the
// token-endpoint proof, IDJAGDPoPProofWith(key, "POST", target, IDJAGDPoPProofOptions{}).
func IDJAGDPoPProof(key *IDJAGDPoPKey, target string) (string, error) {
	return IDJAGDPoPProofWith(key, "POST", target, IDJAGDPoPProofOptions{})
}

// IDJAGDPoPProofWith is a DPoP proof made with the key for one request: method to target, with
// the access token's hash (ath) and the server's nonce when opts has them. Each proof has a
// fresh jti and iat, and its header's jwk is the key's public half only (kty, crv, x, y). For a
// call with the DPoP-bound access token RedeemIDJAG returned (token_type DPoP), send
// Authorization: DPoP <token> and DPoP: a proof for that call's method and URL with
// AccessToken set.
//
// htm is method trimmed and uppercased; "" (or only blanks) is POST, and a method with anything
// but RFC 9110 token characters is a *ConfigError.
//
// htu is target's scheme, host and path: scheme and host lowercased, the default port dropped,
// "/" for an empty path, no query or fragment. The path is the one Go's HTTP client sends,
// URL.EscapedPath: as written when that is a valid percent-encoding, otherwise re-escaped (a
// space becomes %20), never decoded; its "." and ".." segments (also written %2e) are resolved.
// A target that is not an absolute URL, or has an invalid port, is a *ConfigError.
func IDJAGDPoPProofWith(key *IDJAGDPoPKey, method, target string, opts IDJAGDPoPProofOptions) (string, error) {
	signer, err := key.signer()
	if err != nil {
		return "", err
	}
	htm, err := dpopHTM(method)
	if err != nil {
		return "", err
	}
	htu, err := dpopHTU(target)
	if err != nil {
		return "", err
	}
	claims := map[string]interface{}{"htm": htm, "htu": htu, "iat": time.Now().Unix(), "jti": randomID()}
	if opts.AccessToken != "" {
		sum := sha256.Sum256([]byte(opts.AccessToken))
		claims["ath"] = b64url(sum[:])
	}
	if opts.Nonce != "" {
		claims["nonce"] = opts.Nonce
	}
	// signer.publicJWK is made from the private key, never taken from key.PublicJWK.
	return signer.sign(map[string]interface{}{"typ": "dpop+jwt", "jwk": signer.publicJWK}, claims)
}

// dpopHTM is a proof's htm: method trimmed and uppercased, POST when nothing is left. A method
// with anything but RFC 9110 token characters is a *ConfigError (checked before uppercasing, so
// no non-ASCII letter turns into an ASCII one).
func dpopHTM(method string) (string, error) {
	m := strings.TrimSpace(method)
	if m == "" {
		return "POST", nil
	}
	for i := 0; i < len(m); i++ {
		if !isTChar(m[i]) {
			return "", &ConfigError{Message: fmt.Sprintf("touchque: a DPoP proof's method must be an HTTP method (RFC 9110 token characters), not %q", method)}
		}
	}
	return strings.ToUpper(m), nil
}

// isTChar says whether c is an RFC 9110 token character (tchar).
func isTChar(c byte) bool {
	return c >= '0' && c <= '9' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || strings.IndexByte("!#$%&'*+-.^_`|~", c) >= 0
}

// htuDefaultPorts are the ports htu leaves out.
var htuDefaultPorts = map[string]string{"http": "80", "https": "443", "ws": "80", "wss": "443", "ftp": "21"}

// dpopHTU is a proof's htu for target (see IDJAGDPoPProofWith). The path is EscapedPath, the
// one Go sends in the request line, with its dot segments resolved.
func dpopHTU(target string) (string, error) {
	u, err := url.Parse(target)
	if err != nil {
		return "", &ConfigError{Message: "touchque: a DPoP proof needs an absolute URL: " + err.Error()}
	}
	if u.Scheme == "" || u.Host == "" {
		return "", &ConfigError{Message: fmt.Sprintf("touchque: a DPoP proof needs an absolute URL, not %q", target)}
	}
	scheme := strings.ToLower(u.Scheme)
	host, port := strings.TrimSuffix(u.Host, ":"), u.Port()
	if port != "" {
		host = strings.TrimSuffix(host, ":"+port)
		n, err := strconv.Atoi(port)
		if err != nil || n > 65535 {
			return "", &ConfigError{Message: fmt.Sprintf("touchque: %q has an invalid port", target)}
		}
		if port = strconv.Itoa(n); port != htuDefaultPorts[scheme] {
			host += ":" + port
		}
	}
	return scheme + "://" + strings.ToLower(host) + resolveDotSegments(u.EscapedPath()), nil
}

// resolveDotSegments resolves the "." and ".." segments of an escaped path (also written with
// %2e, in either case); an empty path is "/".
func resolveDotSegments(p string) string {
	segments := strings.Split(strings.TrimPrefix(p, "/"), "/")
	out := make([]string, 0, len(segments))
	for i, s := range segments {
		last := i == len(segments)-1
		switch strings.ToLower(s) {
		case "..", ".%2e", "%2e.", "%2e%2e":
			if len(out) > 0 {
				out = out[:len(out)-1]
			}
			if last {
				out = append(out, "")
			}
		case ".", "%2e":
			if last {
				out = append(out, "")
			}
		default:
			out = append(out, s)
		}
	}
	return "/" + strings.Join(out, "/")
}

// IDJAGVerifier checks the ID-JAG an authenticated client presents (jwt-bearer grant).
type IDJAGVerifier struct {
	cfg     IDJAGVerifierConfig
	mu      sync.Mutex
	jwksURI string
	keys    map[string]crypto.PublicKey
	keysAt  time.Time
	triedAt time.Time
	seen    map[string]int64
}

// NewIDJAGVerifier needs Issuer and Audience.
func NewIDJAGVerifier(cfg IDJAGVerifierConfig) (*IDJAGVerifier, error) {
	if cfg.Issuer == "" || cfg.Audience == "" {
		return nil, errors.New("touchque: IDJAGVerifier needs Issuer (the identity provider) and Audience (your authorization server's issuer)")
	}
	if cfg.ClockSkew == 0 {
		cfg.ClockSkew = 60 * time.Second
	}
	if cfg.HTTPClient == nil {
		cfg.HTTPClient = &http.Client{Timeout: 5 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	}
	return &IDJAGVerifier{cfg: cfg, jwksURI: cfg.JWKSURI, seen: map[string]int64{}}, nil
}

func xaaGetJSON(ctx context.Context, client *http.Client, target string) (map[string]interface{}, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", target, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("%s answered %d", target, resp.StatusCode)
	}
	out := map[string]interface{}{}
	return out, json.NewDecoder(resp.Body).Decode(&out)
}

func xaaDiscover(ctx context.Context, client *http.Client, issuer string) (map[string]interface{}, error) {
	meta, err := xaaGetJSON(ctx, client, strings.TrimRight(issuer, "/")+"/.well-known/openid-configuration")
	if err != nil {
		return nil, err
	}
	if meta["issuer"] != issuer {
		return nil, errors.New("the identity provider's metadata does not match its issuer")
	}
	return meta, nil
}

func (v *IDJAGVerifier) loadKeys(ctx context.Context) error {
	if v.jwksURI == "" {
		meta, err := xaaDiscover(ctx, v.cfg.HTTPClient, v.cfg.Issuer)
		if err != nil {
			return err
		}
		uri, _ := meta["jwks_uri"].(string)
		if uri == "" {
			return errors.New("the identity provider names no jwks_uri")
		}
		v.jwksURI = uri
	}
	jwks, err := xaaGetJSON(ctx, v.cfg.HTTPClient, v.jwksURI)
	if err != nil {
		return err
	}
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
	return nil
}

func (v *IDJAGVerifier) keyFor(ctx context.Context, kid string) (crypto.PublicKey, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.keysAt.IsZero() || time.Since(v.keysAt) > 10*time.Minute {
		if err := v.loadKeys(ctx); err != nil {
			return nil, err
		}
	}
	if _, ok := v.keys[kid]; !ok && time.Since(v.triedAt) > time.Minute {
		v.triedAt = time.Now()
		if err := v.loadKeys(ctx); err != nil {
			return nil, err
		}
	}
	return v.keys[kid], nil
}

func (v *IDJAGVerifier) rememberOnce(jti string, exp int64) bool {
	v.mu.Lock()
	defer v.mu.Unlock()
	now := time.Now().Unix()
	for k, until := range v.seen {
		if until < now {
			delete(v.seen, k)
		}
	}
	if _, ok := v.seen[jti]; ok {
		return false
	}
	v.seen[jti] = exp + int64(v.cfg.ClockSkew/time.Second)
	return true
}

// Verify checks the ID-JAG and uses it once: its claims, or *IDJAGError (Code invalid_grant).
// An ID-JAG bound to a DPoP key (cnf.jkt) is refused: use VerifyWithDPoP for those.
func (v *IDJAGVerifier) Verify(ctx context.Context, assertion, clientID string) (*IDJAGClaims, error) {
	return v.VerifyWithDPoP(ctx, assertion, clientID, "")
}

// VerifyWithDPoP is Verify with dpopJKT, the thumbprint of the DPoP proof you verified on this
// request ("" when none): an ID-JAG bound to a key (cnf.jkt) is refused without a matching one.
func (v *IDJAGVerifier) VerifyWithDPoP(ctx context.Context, assertion, clientID, dpopJKT string) (*IDJAGClaims, error) {
	bad := func(m string) error { return &IDJAGError{Code: "invalid_grant", Message: m} }
	parts := strings.Split(assertion, ".")
	if len(parts) != 3 {
		return nil, bad("assertion is not a JWT")
	}
	head, err1 := mcpJSONPart(parts[0])
	c, err2 := mcpJSONPart(parts[1])
	if err1 != nil || err2 != nil {
		return nil, bad("assertion is not a JWT")
	}
	if head["typ"] != idJagTyp {
		return nil, bad("not an ID-JAG (typ oauth-id-jag+jwt)")
	}
	alg, _ := head["alg"].(string)
	kid, _ := head["kid"].(string)
	if (alg != "RS256" && alg != "ES256" && alg != "EdDSA") || kid == "" {
		return nil, bad("unsupported signature")
	}
	key, err := v.keyFor(ctx, kid)
	if err != nil {
		return nil, &IDJAGError{Code: "temporarily_unavailable", Message: "the identity provider's keys could not be read: " + err.Error()}
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if key == nil || err != nil || !mcpVerifySignature(parts[0]+"."+parts[1], sig, alg, key) {
		return nil, bad("signature does not verify")
	}
	now := time.Now().Unix()
	skew := int64(v.cfg.ClockSkew / time.Second)
	var auds []interface{}
	if list, ok := c["aud"].([]interface{}); ok {
		auds = list
	} else {
		auds = []interface{}{c["aud"]}
	}
	exp, _ := c["exp"].(float64)
	iat, _ := c["iat"].(float64)
	sub, _ := c["sub"].(string)
	jti, _ := c["jti"].(string)
	switch {
	case c["iss"] != v.cfg.Issuer:
		return nil, bad("another issuer")
	case len(auds) != 1 || auds[0] != v.cfg.Audience:
		return nil, bad("not for this authorization server")
	case c["client_id"] != clientID || clientID == "":
		return nil, bad("issued to another client")
	case exp == 0 || int64(exp)+skew < now:
		return nil, bad("expired")
	case iat == 0 || int64(iat)-skew > now:
		return nil, bad("issued in the future")
	case sub == "" || jti == "":
		return nil, bad("sub and jti are required")
	}
	// Before the jti is spent: a copy without the key cannot use the ID-JAG up.
	cnfJKT := ""
	if raw, ok := c["cnf"]; ok {
		cnf, _ := raw.(map[string]interface{})
		jkt, ok := cnf["jkt"].(string)
		if !ok {
			return nil, bad("unsupported confirmation method (only DPoP cnf.jkt)")
		}
		if dpopJKT == "" {
			return nil, bad("bound to a DPoP key: a DPoP proof with that key is required")
		}
		if dpopJKT != jkt {
			return nil, bad("the DPoP proof was made with another key")
		}
		cnfJKT = jkt
	}
	first := v.cfg.FirstUse
	if first == nil {
		first = v.rememberOnce
	}
	if !first(jti, int64(exp)) {
		return nil, bad("already used")
	}
	out := &IDJAGClaims{Iss: v.cfg.Issuer, Sub: sub, Aud: v.cfg.Audience, ClientID: clientID, JTI: jti, IssuedAt: int64(iat), ExpiresAt: int64(exp), Scopes: []string{}, CnfJKT: cnfJKT, Claims: c}
	if s, _ := c["scope"].(string); s != "" {
		out.Scopes = strings.Split(s, " ")
	}
	out.Resource, _ = c["resource"].(string)
	out.Tenant, _ = c["tenant"].(string)
	out.Email, _ = c["email"].(string)
	if at, ok := c["auth_time"].(float64); ok {
		out.AuthTime = int64(at)
	}
	if amr, ok := c["amr"].([]interface{}); ok {
		for _, a := range amr {
			if s, ok := a.(string); ok {
				out.AMR = append(out.AMR, s)
			}
		}
	}
	return out, nil
}

func xaaSafeURL(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil {
		return false
	}
	host := u.Hostname()
	return u.Scheme == "https" || (u.Scheme == "http" && (host == "localhost" || host == "127.0.0.1" || host == "::1"))
}

// xaaPostForm posts form to a token endpoint with the client's authentication and, with a key,
// a DPoP proof. Only a 2xx answer whose body is one JSON object (at most 1 MiB) is an answer: any
// other status is an *IDJAGError with the body's error (server_error without one), and a 2xx
// without such a body an *IDJAGError invalid_response.
func xaaPostForm(ctx context.Context, client *http.Client, target string, form url.Values, id, secret string, dpopKey *IDJAGDPoPKey) (map[string]interface{}, error) {
	if !xaaSafeURL(target) {
		return nil, fmt.Errorf("touchque: %s must be an https URL", target)
	}
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	}
	body := form.Encode()
	// post sends the form with the client's authentication and, with a key, a fresh proof (new
	// jti and iat) that carries nonce when it is set. data is the JSON object the body starts
	// with (nil when it starts with none), whole whether that object is all of the body.
	post := func(nonce string) (resp *http.Response, data map[string]interface{}, whole bool, err error) {
		req, err := http.NewRequestWithContext(ctx, "POST", target, strings.NewReader(body))
		if err != nil {
			return nil, nil, false, err
		}
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("Accept", "application/json")
		if dpopKey != nil {
			proof, err := IDJAGDPoPProofWith(dpopKey, "POST", target, IDJAGDPoPProofOptions{Nonce: nonce})
			if err != nil {
				return nil, nil, false, err
			}
			req.Header.Set("DPoP", proof)
		}
		if secret != "" {
			req.SetBasicAuth(url.QueryEscape(id), url.QueryEscape(secret))
		}
		if resp, err = client.Do(req); err != nil {
			return nil, nil, false, err
		}
		defer resp.Body.Close()
		data, whole = xaaJSONObject(resp.Body)
		return resp, data, whole, nil
	}
	resp, data, whole, err := post("")
	if err != nil {
		return nil, err
	}
	nonce := xaaDPoPNonce(resp.Header)
	// The server wants its nonce in the proof (RFC 9449 section 8): the same request once more
	// with a new proof that carries it, never a loop, and only with a nonce of valid syntax.
	if dpopKey != nil && nonce != "" && xaaNonceAsked(resp, data) {
		if resp, data, whole, err = post(nonce); err != nil {
			return nil, err
		}
		if n := xaaDPoPNonce(resp.Header); n != "" {
			nonce = n
		}
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		code, _ := data["error"].(string)
		msg, _ := data["error_description"].(string)
		if code == "" {
			code = "server_error"
		}
		if msg == "" {
			msg = fmt.Sprintf("%s answered %d", target, resp.StatusCode)
		}
		return nil, &IDJAGError{Code: code, Message: msg, Status: resp.StatusCode, DPoPNonce: nonce}
	}
	if data == nil || !whole {
		return nil, &IDJAGError{Code: "invalid_response", Message: fmt.Sprintf("%s answered %d without a JSON object of at most 1 MiB", target, resp.StatusCode),
			Status: resp.StatusCode, DPoPNonce: nonce}
	}
	return data, nil
}

// xaaJSONObject reads body (at most 1 MiB): the JSON object it starts with, nil when it does
// not start with one (no body, null, an array or other value, cut off, not JSON), and whether
// that object is the whole body, blanks aside.
func xaaJSONObject(body io.Reader) (map[string]interface{}, bool) {
	dec := json.NewDecoder(io.LimitReader(body, 1<<20))
	var data map[string]interface{}
	if err := dec.Decode(&data); err != nil || data == nil {
		return nil, false
	}
	_, err := dec.Token()
	return data, err == io.EOF
}

// xaaDPoPNonce is the answer's DPoP-Nonce when it is one nonce of valid syntax (RFC 9449:
// 1*NQCHAR, printable ASCII but space, double quote and backslash); "" when the header is
// missing, empty or invalid, or comes more than once with different values.
func xaaDPoPNonce(h http.Header) string {
	values := h.Values("DPoP-Nonce")
	if len(values) == 0 {
		return ""
	}
	for _, v := range values[1:] {
		if v != values[0] {
			return ""
		}
	}
	nonce := values[0]
	if nonce == "" {
		return ""
	}
	for i := 0; i < len(nonce); i++ {
		if c := nonce[i]; c < 0x21 || c > 0x7e || c == '"' || c == '\\' {
			return ""
		}
	}
	return nonce
}

// xaaNonceAsked says whether an answer asks for a DPoP nonce: a 400 or 401 with error
// use_dpop_nonce, or a 401 whose WWW-Authenticate DPoP challenge has error="use_dpop_nonce".
func xaaNonceAsked(resp *http.Response, data map[string]interface{}) bool {
	if resp.StatusCode != 400 && resp.StatusCode != 401 {
		return false
	}
	return data["error"] == "use_dpop_nonce" || (resp.StatusCode == 401 && xaaNonceChallenge(resp.Header))
}

// xaaNonceChallenge reads WWW-Authenticate (RFC 9110 section 11.6.1): items split at commas
// outside quoted strings; one that is not name=value starts a challenge (its scheme, then maybe
// its first parameter). Each line takes a few passes, so a long header costs linear time.
func xaaNonceChallenge(h http.Header) bool {
	for _, line := range h.Values("WWW-Authenticate") {
		dpop := false
		for _, item := range splitUnquoted(line) {
			name, rest := authToken(item)
			if name == "" && rest == "" {
				continue
			}
			if !strings.HasPrefix(rest, "=") {
				dpop = strings.EqualFold(name, "DPoP")
				name, rest = authToken(rest)
			}
			if dpop && strings.EqualFold(name, "error") && strings.HasPrefix(rest, "=") && strings.Trim(strings.TrimSpace(rest[1:]), `"`) == "use_dpop_nonce" {
				return true
			}
		}
	}
	return false
}

// splitUnquoted splits a header list at the commas outside quoted strings.
func splitUnquoted(s string) []string {
	var out []string
	start, quoted := 0, false
	for i := 0; i < len(s); i++ {
		switch {
		case quoted && s[i] == '\\':
			i++
		case s[i] == '"':
			quoted = !quoted
		case !quoted && s[i] == ',':
			out = append(out, s[start:i])
			start = i + 1
		}
	}
	return append(out, s[start:])
}

// authToken is s's leading token (RFC 9110 tchar) and the rest, blanks trimmed.
func authToken(s string) (string, string) {
	s = strings.TrimLeft(s, " \t")
	i := 0
	for i < len(s) && isTChar(s[i]) {
		i++
	}
	return s[:i], strings.TrimLeft(s[i:], " \t")
}

// RequestIDJAGParams: the identity provider (Issuer, or TokenEndpoint), your app there and its
// secret, the member's ID token, and the other service's authorization server (Audience).
type RequestIDJAGParams struct {
	Issuer        string
	TokenEndpoint string
	ClientID      string
	ClientSecret  string
	IDToken       string
	Audience      string
	Resource      string
	Scope         string
	// DPoPKey binds the ID-JAG to this key (DPoP, RFC 9449); redeem it with the same key.
	DPoPKey    *IDJAGDPoPKey
	HTTPClient *http.Client
}

// IDJAG is the grant the identity provider issued.
type IDJAG struct {
	Assertion string
	ExpiresIn int
	Scope     string
	// DPoPBound: with a DPoPKey, whether the returned ID-JAG carries that key's thumbprint
	// (cnf.jkt); an identity provider without DPoP support ignores the proof.
	DPoPBound bool
}

// RequestIDJAG trades a member's ID token for an ID-JAG (token exchange, client_secret_basic).
// A token endpoint answer other than a 2xx with an ID-JAG is an *IDJAGError.
func RequestIDJAG(ctx context.Context, p RequestIDJAGParams) (*IDJAG, error) {
	var signer *Agent
	if p.DPoPKey != nil {
		var err error
		if signer, err = p.DPoPKey.signer(); err != nil { // before the identity provider is asked anything
			return nil, err
		}
	}
	endpoint := p.TokenEndpoint
	if endpoint == "" {
		if p.Issuer == "" {
			return nil, errors.New("touchque: RequestIDJAG needs Issuer or TokenEndpoint")
		}
		client := p.HTTPClient
		if client == nil {
			client = &http.Client{Timeout: 5 * time.Second}
		}
		meta, err := xaaDiscover(ctx, client, p.Issuer)
		if err != nil {
			return nil, err
		}
		endpoint, _ = meta["token_endpoint"].(string)
		if endpoint == "" {
			return nil, errors.New("touchque: the identity provider names no token_endpoint")
		}
	}
	form := url.Values{"grant_type": {TokenExchangeGrant}, "requested_token_type": {IDJAGTokenType}, "subject_token": {p.IDToken},
		"subject_token_type": {IDTokenTokenType}, "audience": {p.Audience}}
	if p.Resource != "" {
		form.Set("resource", p.Resource)
	}
	if p.Scope != "" {
		form.Set("scope", p.Scope)
	}
	data, err := xaaPostForm(ctx, p.HTTPClient, endpoint, form, p.ClientID, p.ClientSecret, p.DPoPKey)
	if err != nil {
		return nil, err
	}
	assertion, _ := data["access_token"].(string)
	if data["issued_token_type"] != IDJAGTokenType || assertion == "" {
		return nil, &IDJAGError{Code: "invalid_response", Message: "the identity provider did not answer with an ID-JAG"}
	}
	out := &IDJAG{Assertion: assertion}
	if n, ok := data["expires_in"].(float64); ok {
		out.ExpiresIn = int(n)
	}
	out.Scope, _ = data["scope"].(string)
	if signer != nil {
		if parts := strings.Split(assertion, "."); len(parts) == 3 {
			if c, err := mcpJSONPart(parts[1]); err == nil {
				cnf, _ := c["cnf"].(map[string]interface{})
				jkt, _ := cnf["jkt"].(string)
				// The thumbprint of the key the proof was signed with, not the editable field.
				out.DPoPBound = jkt != "" && jkt == JWKThumbprint(signer.publicJWK)
			}
		}
	}
	return out, nil
}

// RedeemIDJAGParams: the other service's token endpoint, your client there, the ID-JAG.
type RedeemIDJAGParams struct {
	TokenEndpoint string
	ClientID      string
	ClientSecret  string
	Assertion     string
	Resource      string
	Scope         string
	// DPoPKey is the key the ID-JAG is bound to: a DPoP proof goes along. An authorization server
	// that supports DPoP binds the access token to the key too (token_type DPoP); one that does
	// not issues a Bearer token.
	DPoPKey    *IDJAGDPoPKey
	HTTPClient *http.Client
}

// RedeemIDJAG trades an ID-JAG for an access token at the other service (jwt-bearer): the token
// endpoint's JSON answer. A refusal, any other non-2xx answer (redirects are not followed with
// the default client) and a 2xx whose body is not a JSON object are an *IDJAGError.
func RedeemIDJAG(ctx context.Context, p RedeemIDJAGParams) (map[string]interface{}, error) {
	form := url.Values{"grant_type": {JWTBearerGrant}, "assertion": {p.Assertion}}
	if p.ClientSecret == "" {
		form.Set("client_id", p.ClientID)
	}
	if p.Resource != "" {
		form.Set("resource", p.Resource)
	}
	if p.Scope != "" {
		form.Set("scope", p.Scope)
	}
	return xaaPostForm(ctx, p.HTTPClient, p.TokenEndpoint, form, p.ClientID, p.ClientSecret, p.DPoPKey)
}
