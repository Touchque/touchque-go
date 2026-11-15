package touchque

import (
	"bufio"
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"
)

// Cross App Access (ID-JAG) and A2A agent card signatures against the shared
// fake API: an app trades a member's ID token for an ID-JAG at the identity
// provider and redeems it; an authorization server checks one (issuer,
// audience, client, expiry, typ, once); a card signed in RFC 8785 form by the
// fake (JavaScript) verifies here with keys from its own host and fails when
// changed or pointed elsewhere.

func idJagReason(err error) string {
	var e *IDJAGError
	if errors.As(err, &e) {
		return e.Message
	}
	if err == nil {
		return "accepted"
	}
	return err.Error()
}

func TestCrossAppAccess(t *testing.T) {
	api := startFakeAPI(t)
	ctx := context.Background()
	jag, err := RequestIDJAG(ctx, RequestIDJAGParams{Issuer: api.baseURL + "/idp", ClientID: "tqapp_test", ClientSecret: "tqs_test", IDToken: "idtoken:ada", Audience: "https://rs.example", Resource: "https://rs.example/files"})
	if err != nil || jag.Scope != "files:read" {
		t.Fatal(jag, err)
	}
	_, err = RequestIDJAG(ctx, RequestIDJAGParams{Issuer: api.baseURL + "/idp", ClientID: "tqapp_test", ClientSecret: "wrong", IDToken: "idtoken:ada", Audience: "https://rs.example"})
	var e *IDJAGError
	if !errors.As(err, &e) || e.Code != "invalid_client" || e.Status != 401 {
		t.Fatal(err)
	}
	v, _ := NewIDJAGVerifier(IDJAGVerifierConfig{Issuer: api.baseURL + "/idp", Audience: "https://rs.example"})
	claims, err := v.Verify(ctx, jag.Assertion, "acme-at-rs")
	if err != nil || claims.Sub != "ada" || claims.Resource != "https://rs.example/files" || strings.Join(claims.Scopes, " ") != "files:read" {
		t.Fatal(claims, err)
	}
	if got := idJagReason(func() error { _, err := v.Verify(ctx, jag.Assertion, "acme-at-rs"); return err }()); got != "already used" {
		t.Fatal(got)
	}
	tokens, err := RedeemIDJAG(ctx, RedeemIDJAGParams{TokenEndpoint: api.baseURL + "/rs/token", ClientID: "acme-at-rs", Assertion: jag.Assertion})
	if err != nil || tokens["token_type"] != "Bearer" {
		t.Fatal(tokens, err)
	}

	mint := func(claims map[string]interface{}, typ string) string {
		body := map[string]interface{}{"claims": claims}
		if typ != "" {
			body["typ"] = typ
		}
		return fakePost(t, api.baseURL, "/__test/id-jag", body)["assertion"].(string)
	}
	check := func(assertion, client string) string {
		_, err := v.Verify(ctx, assertion, client)
		return idJagReason(err)
	}
	cases := []struct{ got, want string }{
		{check(mint(nil, ""), "someone-else"), "issued to another client"},
		{check(mint(map[string]interface{}{"aud": "https://evil.example"}, ""), "acme-at-rs"), "not for this authorization server"},
		{check(mint(map[string]interface{}{"aud": []string{"https://rs.example", "https://b.example"}}, ""), "acme-at-rs"), "not for this authorization server"},
		{check(mint(map[string]interface{}{"iss": "https://evil.example"}, ""), "acme-at-rs"), "another issuer"},
		{check(mint(nil, "at+jwt"), "acme-at-rs"), "not an ID-JAG (typ oauth-id-jag+jwt)"},
		{check(mint(map[string]interface{}{"exp": time.Now().Unix() - 600}, ""), "acme-at-rs"), "expired"},
	}
	for i, c := range cases {
		if c.got != c.want {
			t.Fatalf("case %d: %q, want %q", i, c.got, c.want)
		}
	}
	parts := strings.Split(mint(nil, ""), ".")
	raw, _ := base64.RawURLEncoding.DecodeString(parts[1])
	var m map[string]interface{}
	_ = json.Unmarshal(raw, &m)
	m["sub"] = "mallory"
	forged, _ := json.Marshal(m)
	if got := check(parts[0]+"."+base64.RawURLEncoding.EncodeToString(forged)+"."+parts[2], "acme-at-rs"); got != "signature does not verify" {
		t.Fatal(got)
	}
}

func TestCrossAppAccessDPoP(t *testing.T) {
	ctx := context.Background()
	// An identity provider and an authorization server that check the proof and bind to its key.
	type seenProof struct {
		path    string
		header  map[string]interface{}
		payload map[string]interface{}
		jkt     string
	}
	var seen []seenProof
	enc := func(v interface{}) string { b, _ := json.Marshal(v); return base64.RawURLEncoding.EncodeToString(b) }
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		parts := strings.Split(r.Header.Get("DPoP"), ".")
		if len(parts) != 3 {
			w.WriteHeader(400)
			return
		}
		header, _ := mcpJSONPart(parts[0])
		payload, _ := mcpJSONPart(parts[1])
		jwk, _ := header["jwk"].(map[string]interface{})
		pub, err := mcpPublicKey(jwk)
		sig, _ := base64.RawURLEncoding.DecodeString(parts[2])
		ok := err == nil && mcpVerifySignature(parts[0]+"."+parts[1], sig, "ES256", pub)
		seen = append(seen, seenProof{r.URL.RequestURI(), header, payload, JWKThumbprint(jwk)})
		w.Header().Set("Content-Type", "application/json")
		if !ok {
			w.WriteHeader(400)
			_, _ = w.Write([]byte(`{"error":"invalid_dpop_proof"}`))
			return
		}
		if r.URL.RequestURI() == "/idp/token?x=1" {
			jag := enc(map[string]string{"typ": "oauth-id-jag+jwt", "alg": "RS256"}) + "." + enc(map[string]interface{}{"cnf": map[string]string{"jkt": JWKThumbprint(jwk)}}) + ".sig"
			_ = json.NewEncoder(w).Encode(map[string]string{"access_token": jag, "issued_token_type": IDJAGTokenType, "token_type": "N_A"})
			return
		}
		_, _ = w.Write([]byte(`{"access_token":"at","token_type":"DPoP"}`))
	}))
	defer srv.Close()
	key, err := NewIDJAGDPoPKey()
	if err != nil {
		t.Fatal(err)
	}
	got, err := RequestIDJAG(ctx, RequestIDJAGParams{TokenEndpoint: srv.URL + "/idp/token?x=1", ClientID: "tqapp_test", ClientSecret: "tqs_test", IDToken: "idtoken:ada", Audience: "https://rs.example", DPoPKey: key})
	if err != nil || !got.DPoPBound {
		t.Fatal(got, err)
	}
	tokens, err := RedeemIDJAG(ctx, RedeemIDJAGParams{TokenEndpoint: srv.URL + "/rs/token", ClientID: "acme-at-rs", Assertion: got.Assertion, DPoPKey: key})
	if err != nil || tokens["token_type"] != "DPoP" {
		t.Fatal(tokens, err)
	}
	if len(seen) != 2 {
		t.Fatalf("%d proofs", len(seen))
	}
	if seen[0].header["typ"] != "dpop+jwt" || seen[0].header["alg"] != "ES256" || seen[0].jkt != key.Thumbprint || seen[0].header["jwk"].(map[string]interface{})["d"] != nil {
		t.Fatal(seen[0].header)
	}
	if seen[0].payload["htm"] != "POST" || seen[0].payload["htu"] != srv.URL+"/idp/token" {
		t.Fatal(seen[0].payload)
	}
	if seen[1].payload["htu"] != srv.URL+"/rs/token" || seen[1].jkt != key.Thumbprint || seen[0].payload["jti"] == seen[1].payload["jti"] {
		t.Fatal(seen[1].payload)
	}

	// An identity provider that ignores DPoP answers with a bearer ID-JAG: DPoPBound false.
	api := startFakeAPI(t)
	other, _ := NewIDJAGDPoPKey()
	plainJag, err := RequestIDJAG(ctx, RequestIDJAGParams{Issuer: api.baseURL + "/idp", ClientID: "tqapp_test", ClientSecret: "tqs_test", IDToken: "idtoken:ada", Audience: "https://rs.example", DPoPKey: other})
	if err != nil || plainJag.DPoPBound {
		t.Fatal(plainJag, err)
	}

	// The verifier: a bound ID-JAG needs the proof key's thumbprint, refused before it is used up.
	v, _ := NewIDJAGVerifier(IDJAGVerifierConfig{Issuer: api.baseURL + "/idp", Audience: "https://rs.example"})
	mint := func(claims map[string]interface{}) string {
		return fakePost(t, api.baseURL, "/__test/id-jag", map[string]interface{}{"claims": claims})["assertion"].(string)
	}
	check := func(assertion, jkt string) string {
		_, err := v.VerifyWithDPoP(ctx, assertion, "acme-at-rs", jkt)
		return idJagReason(err)
	}
	bound := mint(map[string]interface{}{"cnf": map[string]string{"jkt": "right-key-thumbprint"}})
	if got := idJagReason(func() error { _, err := v.Verify(ctx, bound, "acme-at-rs"); return err }()); got != "bound to a DPoP key: a DPoP proof with that key is required" {
		t.Fatal(got)
	}
	if got := check(bound, "other-key"); got != "the DPoP proof was made with another key" {
		t.Fatal(got)
	}
	claims, err := v.VerifyWithDPoP(ctx, bound, "acme-at-rs", "right-key-thumbprint")
	if err != nil || claims.CnfJKT != "right-key-thumbprint" || claims.Sub == "" {
		t.Fatal(claims, err)
	}
	if got := check(mint(map[string]interface{}{"cnf": map[string]string{"x5t": "abc"}}), "x"); got != "unsupported confirmation method (only DPoP cnf.jkt)" {
		t.Fatal(got)
	}
	// Unbound: as before, with or without a proof key.
	claims, err = v.VerifyWithDPoP(ctx, mint(map[string]interface{}{}), "acme-at-rs", "any")
	if err != nil || claims.CnfJKT != "" {
		t.Fatal(claims, err)
	}
}

// parseDPoPProof checks a proof's ES256 signature with the jwk in its header and returns its
// header and payload (numbers as written: json.Number).
func parseDPoPProof(proof string) (header, payload map[string]interface{}, err error) {
	parts := strings.Split(proof, ".")
	if len(parts) != 3 {
		return nil, nil, fmt.Errorf("not a compact JWS: %q", proof)
	}
	if header, err = mcpJSONPart(parts[0]); err != nil {
		return nil, nil, err
	}
	raw, _ := base64.RawURLEncoding.DecodeString(parts[1])
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	if err = d.Decode(&payload); err != nil {
		return nil, nil, err
	}
	jwk, _ := header["jwk"].(map[string]interface{})
	pub, err := mcpPublicKey(jwk)
	sig, _ := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil || len(sig) != 64 || !mcpVerifySignature(parts[0]+"."+parts[1], sig, "ES256", pub) {
		return nil, nil, fmt.Errorf("the proof does not verify with its jwk (%d-byte signature, %v)", len(sig), err)
	}
	return header, payload, nil
}

func dpopProof(t *testing.T, proof string) (map[string]interface{}, map[string]interface{}) {
	t.Helper()
	header, payload, err := parseDPoPProof(proof)
	if err != nil {
		t.Fatal(err)
	}
	return header, payload
}

func TestIDJAGDPoPProofWith(t *testing.T) {
	key, err := NewIDJAGDPoPKey()
	if err != nil {
		t.Fatal(err)
	}
	// The token-endpoint form keeps working: POST, no ath, no nonce.
	proof, err := IDJAGDPoPProof(key, "https://sso.touchque.com/sso/token?x=1#f")
	if err != nil {
		t.Fatal(err)
	}
	header, payload := dpopProof(t, proof)
	jwk, _ := header["jwk"].(map[string]interface{})
	x, _ := jwk["x"].(string)
	y, _ := jwk["y"].(string)
	if header["typ"] != "dpop+jwt" || header["alg"] != "ES256" || len(header) != 3 || len(jwk) != 4 || jwk["kty"] != "EC" || jwk["crv"] != "P-256" ||
		len(x) != 43 || len(y) != 43 || JWKThumbprint(jwk) != key.Thumbprint {
		t.Fatal(header)
	}
	iat, err := payload["iat"].(json.Number).Int64()
	if now := time.Now().Unix(); err != nil || iat < now-5 || iat > now {
		t.Fatalf("iat %v: %v", payload["iat"], err)
	}
	if jti, _ := payload["jti"].(string); len(payload) != 4 || payload["htm"] != "POST" || payload["htu"] != "https://sso.touchque.com/sso/token" || len(jti) < 16 {
		t.Fatal(payload)
	}

	// A call with the DPoP-bound access token: the method uppercased, ath, and a nonce.
	token := "Kz~8mXK1EalYznwH-LC-1fBAo.4Ljp~zsPE_NeO.gxU" // RFC 9449 section 7.1
	proof, err = IDJAGDPoPProofWith(key, "get", "https://API.Example.com:443/v1/files?x=1", IDJAGDPoPProofOptions{AccessToken: token, Nonce: "n-1"})
	if err != nil {
		t.Fatal(err)
	}
	_, call := dpopProof(t, proof)
	if len(call) != 6 || call["htm"] != "GET" || call["htu"] != "https://api.example.com/v1/files" || call["ath"] != "fUHyO2r2Z3DZ53EsNrWBb0xWXoaNy59IiKCAqksmQEo" ||
		call["nonce"] != "n-1" || call["jti"] == payload["jti"] {
		t.Fatal(call)
	}
	other := "another-access-token"
	sum := sha256.Sum256([]byte(other))
	proof, _ = IDJAGDPoPProofWith(key, "DELETE", "https://files.example/v1/files/7", IDJAGDPoPProofOptions{AccessToken: other})
	if _, del := dpopProof(t, proof); del["htm"] != "DELETE" || del["ath"] != base64.RawURLEncoding.EncodeToString(sum[:]) || del["nonce"] != nil {
		t.Fatal(del)
	}
	// "" is POST; no options, no ath and no nonce, and "" for either is left out too.
	proof, _ = IDJAGDPoPProofWith(key, "", "https://as.example/token", IDJAGDPoPProofOptions{})
	if _, post := dpopProof(t, proof); len(post) != 4 || post["htm"] != "POST" {
		t.Fatal(post)
	}
	proof, _ = IDJAGDPoPProofWith(key, "GET", "https://as.example/r", IDJAGDPoPProofOptions{AccessToken: "", Nonce: ""})
	if _, empty := dpopProof(t, proof); len(empty) != 4 || empty["ath"] != nil || empty["nonce"] != nil {
		t.Fatal(empty)
	}
	// A nonce given by hand goes in as it is: its syntax is not checked.
	for _, nonce := range []string{"a b", `"n-1"`, `n\1`, "nönce"} {
		proof, err := IDJAGDPoPProofWith(key, "GET", "https://as.example/r", IDJAGDPoPProofOptions{Nonce: nonce})
		if err != nil {
			t.Fatalf("%q: %v", nonce, err)
		}
		if _, p := dpopProof(t, proof); p["nonce"] != nonce {
			t.Errorf("%q: nonce %v", nonce, p["nonce"])
		}
	}
	// Each proof its own jti.
	seen := map[interface{}]bool{}
	for i := 0; i < 50; i++ {
		proof, _ := IDJAGDPoPProof(key, "https://as.example/token")
		if _, p := dpopProof(t, proof); seen[p["jti"]] {
			t.Fatal("a jti came twice")
		} else {
			seen[p["jti"]] = true
		}
	}
}

func TestIDJAGDPoPProofHTU(t *testing.T) {
	key, _ := NewIDJAGDPoPKey()
	// For these URLs the htu is what a WHATWG URL parser (Node's new URL) makes of each,
	// protocol//host + pathname; that is not so for every URL (an IDN host is not converted).
	for target, want := range map[string]string{
		"https://API.Example.com:443/v1/files?x=1#f": "https://api.example.com/v1/files",
		"HTTP://Example.COM:80":                      "http://example.com/",
		"https://as.example?x=1":                     "https://as.example/",
		"https://as.example:8443/token?x":            "https://as.example:8443/token",
		"https://as.example:0443/x":                  "https://as.example/x",
		"https://as.example:/x":                      "https://as.example/x",
		"http://127.0.0.1:80/t":                      "http://127.0.0.1/t",
		"https://[::1]:8443/x":                       "https://[::1]:8443/x",
		"https://user:pw@as.example/x":               "https://as.example/x",
		// The path as sent, percent-encoding kept: never the decoded path.
		"https://as.example/t/a%2Fb/token":       "https://as.example/t/a%2Fb/token",
		"https://as.example/%7Euser/token":       "https://as.example/%7Euser/token",
		"https://as.example/realms/my%20realm/x": "https://as.example/realms/my%20realm/x",
		"https://as.example/a b":                 "https://as.example/a%20b",
		"https://as.example/é":                   "https://as.example/%C3%A9",
		"https://as.example//a":                  "https://as.example//a",
		// "." and ".." segments kept as written (also %2e): net/http sends them so.
		"https://as.example/a/./b/../c": "https://as.example/a/./b/../c",
		"https://as.example/a/%2e%2E/c": "https://as.example/a/%2e%2E/c",
		"https://as.example/a/b/..":     "https://as.example/a/b/..",
		"https://as.example/a/b/.":      "https://as.example/a/b/.",
		"https://as.example/..":         "https://as.example/..",
		"HTTPS://AS.example/x":          "https://as.example/x",
	} {
		proof, err := IDJAGDPoPProofWith(key, "GET", target, IDJAGDPoPProofOptions{})
		if err != nil {
			t.Fatalf("%s: %v", target, err)
		}
		if _, payload := dpopProof(t, proof); payload["htu"] != want {
			t.Errorf("%s: htu %v, want %s", target, payload["htu"], want)
		}
	}
	// Not an absolute http or https URL with a host: a *ConfigError, from both helpers.
	var ce *ConfigError
	for _, target := range []string{"", "/token", "as.example/token", "https:as.example/token", "https://as.example:99999/t", "https://as.example/a%zz",
		"ftp://as.example/x", "ws://as.example/x", "wss://as.example/x", "file:///etc/passwd", "mailto:a@as.example", "urn:ietf:x", "javascript:alert(1)",
		"data:text/plain,x", "httpx://as.example/x", "https:///token", "https://:443/token", "http://user@/token"} {
		if proof, err := IDJAGDPoPProof(key, target); !errors.As(err, &ce) {
			t.Errorf("%q: %s %v", target, proof, err)
		}
		if proof, err := IDJAGDPoPProofWith(key, "GET", target, IDJAGDPoPProofOptions{AccessToken: "at"}); !errors.As(err, &ce) {
			t.Errorf("%q, IDJAGDPoPProofWith: %s %v", target, proof, err)
		}
	}
}

// A proof's htu path is the one net/http puts in the request line (RequestURI): the token
// endpoint's server sees, for every one of these URLs, the path the proof names, and the public
// helper makes the same htu.
func TestIDJAGDPoPHTUIsThePathSent(t *testing.T) {
	key, _ := NewIDJAGDPoPKey()
	type sent struct{ target, htu string }
	var mu sync.Mutex
	var got []sent
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, proof, err := parseDPoPProof(r.Header.Get("DPoP"))
		if err != nil {
			t.Error(err)
		}
		mu.Lock()
		got = append(got, sent{r.RequestURI, fmt.Sprint(proof["htu"])})
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"access_token":"at","token_type":"DPoP"}`)
	}))
	defer srv.Close()
	for _, path := range []string{"", "/", "/a/../token", "/x/./token", "/a/%2e%2e/token", "/a/%2E./b/.%2e/", "/a/b/..", "/..", "/t/%7e", "/t/a%20b",
		"/t/a b", "/t/a~b", "/t/a|b", "/t/é", "/t/a%2Fb", "//token", `/t/a\b`, "/token/", "/a/../token?x=/../y#f"} {
		mu.Lock()
		got = nil
		mu.Unlock()
		if _, err := RedeemIDJAG(context.Background(), RedeemIDJAGParams{TokenEndpoint: srv.URL + path, ClientID: "acme", ClientSecret: "s", Assertion: "a.b.c", DPoPKey: key}); err != nil {
			t.Errorf("%q: %v", path, err)
			continue
		}
		mu.Lock()
		seen := got
		mu.Unlock()
		if len(seen) != 1 {
			t.Errorf("%q: %d requests", path, len(seen))
			continue
		}
		wire, _, _ := strings.Cut(seen[0].target, "?")
		if seen[0].htu != srv.URL+wire {
			t.Errorf("%q: sent %s, htu %s", path, seen[0].target, seen[0].htu)
		}
		proof, err := IDJAGDPoPProofWith(key, "POST", srv.URL+path, IDJAGDPoPProofOptions{})
		if err != nil {
			t.Fatal(err)
		}
		if _, p := dpopProof(t, proof); p["htu"] != seen[0].htu {
			t.Errorf("%q: IDJAGDPoPProofWith htu %v, the token call's %s", path, p["htu"], seen[0].htu)
		}
	}
}

func TestIDJAGDPoPProofMethod(t *testing.T) {
	key, _ := NewIDJAGDPoPKey()
	// ASCII blanks (space, \t, \r, \n, \v, \f) trimmed, then uppercased; nothing left is POST.
	for method, want := range map[string]string{
		"": "POST", "   ": "POST", "\t\r\n": "POST", "\v\f": "POST", " \t\r\n\v\f": "POST",
		"get": "GET", " get ": "GET", "\tPatch\n": "PATCH", "\vput\f": "PUT", "\r\nGET\r\n": "GET", "DELETE": "DELETE",
		"m-search": "M-SEARCH", "x_custom.1": "X_CUSTOM.1", "!#$%&'*+-.^_`|~": "!#$%&'*+-.^_`|~",
	} {
		proof, err := IDJAGDPoPProofWith(key, method, "https://as.example/x", IDJAGDPoPProofOptions{})
		if err != nil {
			t.Fatalf("%q: %v", method, err)
		}
		if _, p := dpopProof(t, proof); p["htm"] != want {
			t.Errorf("%q: htm %v, want %s", method, p["htm"], want)
		}
	}
	// Anything but RFC 9110 token characters is a *ConfigError, also a letter that uppercases
	// to ASCII (U+017F long s to S, U+0131 dotless i to I), and a NUL or a non-ASCII space, which
	// are not trimmed (U+00A0 no-break space, U+0085 next line, U+2003 em space, U+3000).
	var ce *ConfigError
	for _, method := range []string{"GET /x", "GE T", "GET\r\nX-Injected: 1", `PO"ST`, "GET(", "GET,POST", "GET;", "GET:", "[GET]", "{}",
		"a/b", `a\b`, "a=b", "a@b", "a?b", "p\u00f6st", "po\u017ft", "g\u0131t", "\u0413\u0415\u0422", "GET\x00", "\x7f",
		"\x00", "\x00GET", " GET\x00 ", "\u00a0", "\u00a0GET", "GET\u00a0", " \u00a0GET\u00a0 ", "\u0085GET", "\u2003GET", "\u3000", "\x1cGET", "GET\x1f"} {
		if proof, err := IDJAGDPoPProofWith(key, method, "https://as.example/x", IDJAGDPoPProofOptions{}); !errors.As(err, &ce) {
			t.Errorf("%q: %s %v", method, proof, err)
		}
	}
}

// The jwk in a proof's header is rebuilt from the private key: exactly kty, crv, x and y, whatever
// the exported PublicJWK and Thumbprint fields were changed to; DPoPBound uses the key too.
func TestIDJAGDPoPProofJWKComesFromTheKey(t *testing.T) {
	key, _ := NewIDJAGDPoPKey()
	want := map[string]interface{}{}
	for k, v := range key.PublicJWK {
		want[k] = v
	}
	thumbprint := key.Thumbprint
	key.PublicJWK["d"] = "a-private-member"
	key.PublicJWK["kid"] = "k-1"
	key.PublicJWK["x"] = "AAAA"
	key.Thumbprint = "edited"
	proof, err := IDJAGDPoPProofWith(key, "GET", "https://as.example/x", IDJAGDPoPProofOptions{AccessToken: "at"})
	if err != nil {
		t.Fatal(err)
	}
	header, _ := dpopProof(t, proof) // the signature verifies with the jwk in the header
	jwk, _ := header["jwk"].(map[string]interface{})
	if len(jwk) != 4 || jwk["kty"] != want["kty"] || jwk["crv"] != want["crv"] || jwk["x"] != want["x"] || jwk["y"] != want["y"] || JWKThumbprint(jwk) != thumbprint {
		t.Fatal(jwk)
	}

	enc := func(v interface{}) string { b, _ := json.Marshal(v); return base64.RawURLEncoding.EncodeToString(b) }
	idp := newTokenEndpoint(t, func(_ int, w http.ResponseWriter, _ map[string]interface{}) {
		jag := enc(map[string]string{"typ": "oauth-id-jag+jwt", "alg": "RS256"}) + "." + enc(map[string]interface{}{"cnf": map[string]string{"jkt": thumbprint}}) + ".sig"
		_ = json.NewEncoder(w).Encode(map[string]string{"access_token": jag, "issued_token_type": IDJAGTokenType, "token_type": "N_A"})
	})
	jag, err := RequestIDJAG(context.Background(), RequestIDJAGParams{TokenEndpoint: idp.URL + "/token", ClientID: "app", ClientSecret: "s", IDToken: "id", Audience: "https://rs.example", DPoPKey: key})
	if err != nil || !jag.DPoPBound {
		t.Fatal(jag, err)
	}
}

// Only a DPoP-Nonce of valid syntax (RFC 9449: 1*NQCHAR) is retried with and kept on the error:
// the latest one, from the answer to the retry when that has one, else from the first answer.
func TestIDJAGDPoPNonceSyntax(t *testing.T) {
	ctx := context.Background()
	key, _ := NewIDJAGDPoPKey()
	var every strings.Builder
	for c := byte(0x21); c <= 0x7e; c++ {
		if c != '"' && c != '\\' {
			every.WriteByte(c)
		}
	}
	long := strings.Repeat("n", 8192)
	for name, tc := range map[string]struct {
		first, retry []string // the DPoP-Nonce lines of the first answer and of the retry's answer
		retried      string   // the retry's nonce, "" for no retry
		want         string   // IDJAGError.DPoPNonce
	}{
		"every NQCHAR":            {first: []string{every.String()}, retried: every.String(), want: every.String()},
		"8192 characters":         {first: []string{long}, retry: []string{"n-2"}, retried: long, want: "n-2"},
		"twice, the same value":   {first: []string{"n-1", "n-1"}, retry: []string{"n-2", "n-2"}, retried: "n-1", want: "n-2"},
		"missing":                 {},
		"empty":                   {first: []string{""}},
		"twice, different values": {first: []string{"n-1", "n-2"}},
		// One line joined with ", " (as a proxy or HTTP library combines lines) is the same as two.
		"joined, the same value":       {first: []string{"n-1, n-1"}, retry: []string{"n-2, n-2, n-2"}, retried: "n-1", want: "n-2"},
		"joined and a line, the same":  {first: []string{"n-1, n-1", "n-1"}, retried: "n-1", want: "n-1"},
		"joined, different values":     {first: []string{"n-1, n-2"}},
		"joined and a line, different": {first: []string{"n-1, n-1", "n-2"}},
		"joined, an empty value":       {first: []string{"n-1, , n-1"}},
		"a comma alone is one nonce":   {first: []string{"n-1,n-1"}, retried: "n-1,n-1", want: "n-1,n-1"},
		"joined with two spaces":       {first: []string{"n-1,  n-1"}},
		"a space":                      {first: []string{"n 1"}},
		"a tab":                        {first: []string{"n\t1"}},
		"a double quote":               {first: []string{`n"1`}},
		"quoted":                       {first: []string{`"n-1"`}},
		"a backslash":                  {first: []string{`n\1`}},
		"not ASCII":                    {first: []string{"n\u00f6nce"}},
		"retry answer, none":           {first: []string{"n-1"}, retried: "n-1", want: "n-1"},
		"retry answer, invalid":        {first: []string{"n-1"}, retry: []string{"n 2"}, retried: "n-1", want: "n-1"},
		"retry answer, two values":     {first: []string{"n-1"}, retry: []string{"n-2", "n-3"}, retried: "n-1", want: "n-1"},
	} {
		e := newTokenEndpoint(t, func(n int, w http.ResponseWriter, _ map[string]interface{}) {
			values := tc.first
			if n > 1 {
				values = tc.retry
			}
			if values != nil {
				w.Header()["Dpop-Nonce"] = values
			}
			w.WriteHeader(400)
			_, _ = w.Write([]byte(`{"error":"use_dpop_nonce"}`))
		})
		_, err := RedeemIDJAG(ctx, RedeemIDJAGParams{TokenEndpoint: e.URL + "/token", ClientID: "acme", ClientSecret: "s", Assertion: "a.b.c", DPoPKey: key})
		var ie *IDJAGError
		if !errors.As(err, &ie) || ie.Code != "use_dpop_nonce" || ie.Status != 400 || ie.DPoPNonce != tc.want {
			t.Errorf("%s: %#v", name, err)
			continue
		}
		calls := e.seen()
		if tc.retried == "" {
			if len(calls) != 1 || calls[0].proof["nonce"] != nil {
				t.Errorf("%s: %d requests, want 1", name, len(calls))
			}
		} else if len(calls) != 2 || calls[0].proof["nonce"] != nil || calls[1].proof["nonce"] != tc.retried {
			t.Errorf("%s: %d requests, want a retry with the nonce", name, len(calls))
		}
	}

	// Without a key: no retry, and only a valid nonce on the error.
	for nonce, want := range map[string]string{"n-1": "n-1", "n 1": "", `"n-1"`: ""} {
		e := newTokenEndpoint(t, func(_ int, w http.ResponseWriter, _ map[string]interface{}) {
			w.Header().Set("DPoP-Nonce", nonce)
			w.WriteHeader(400)
			_, _ = w.Write([]byte(`{"error":"use_dpop_nonce"}`))
		})
		_, err := RedeemIDJAG(ctx, RedeemIDJAGParams{TokenEndpoint: e.URL + "/token", ClientID: "acme", ClientSecret: "s", Assertion: "a.b.c"})
		if err := idJagErr(t, err); err.DPoPNonce != want || len(e.seen()) != 1 {
			t.Errorf("%q without a key: %d requests, %+v", nonce, len(e.seen()), err)
		}
	}
}

// A token endpoint's answer is a 2xx whose body is one JSON object; anything else is an
// *IDJAGError, a redirect (not followed) too.
func TestIDJAGTokenEndpointAnswers(t *testing.T) {
	ctx := context.Background()
	type answer struct {
		status   int
		location string
		body     string
	}
	endpoint := func(a answer) *tokenEndpoint {
		return newTokenEndpoint(t, func(_ int, w http.ResponseWriter, _ map[string]interface{}) {
			if a.location != "" {
				w.Header().Set("Location", a.location)
			}
			w.WriteHeader(a.status)
			_, _ = io.WriteString(w, a.body)
		})
	}
	redeem := func(e *tokenEndpoint) (map[string]interface{}, error) {
		return RedeemIDJAG(ctx, RedeemIDJAGParams{TokenEndpoint: e.URL + "/token", ClientID: "acme", ClientSecret: "s", Assertion: "a.b.c"})
	}
	request := func(e *tokenEndpoint) (*IDJAG, error) {
		return RequestIDJAG(ctx, RequestIDJAGParams{TokenEndpoint: e.URL + "/token", ClientID: "app", ClientSecret: "s", IDToken: "id", Audience: "https://rs.example"})
	}

	// Not a 2xx: its error, else server_error, with the status; a redirect is not followed.
	for _, tc := range []struct {
		answer answer
		code   string
	}{
		{answer{301, "/elsewhere", ""}, "server_error"},
		{answer{302, "https://redirected.invalid/token", `{"access_token":"at"}`}, "server_error"},
		{answer{303, "/elsewhere", "<html></html>"}, "server_error"},
		{answer{304, "", ""}, "server_error"},
		{answer{307, "/elsewhere", ""}, "server_error"},
		{answer{308, "/elsewhere", ""}, "server_error"},
		{answer{302, "/elsewhere", `{"error":"temporarily_unavailable","error_description":"moved"}`}, "temporarily_unavailable"},
		{answer{400, "", "<html></html>"}, "server_error"},
		{answer{400, "", `{"error":"invalid_grant"} <!-- an error answer is read up to its object -->`}, "invalid_grant"},
		{answer{503, "", `{"error":"temporarily_unavailable"}`}, "temporarily_unavailable"},
	} {
		e := endpoint(tc.answer)
		tokens, err := redeem(e)
		var ie *IDJAGError
		if !errors.As(err, &ie) || tokens != nil || ie.Code != tc.code || ie.Status != tc.answer.status || len(e.seen()) != 1 {
			t.Errorf("RedeemIDJAG, %+v: %v %#v, %d requests", tc.answer, tokens, err, len(e.seen()))
		}
		jag, err := request(e)
		if !errors.As(err, &ie) || jag != nil || ie.Code != tc.code || ie.Status != tc.answer.status || len(e.seen()) != 2 {
			t.Errorf("RequestIDJAG, %+v: %v %#v, %d requests", tc.answer, jag, err, len(e.seen()))
		}
	}

	// A 2xx whose body is not one JSON object (of at most 1 MiB): invalid_response.
	big := `{"access_token":"` + strings.Repeat("a", 1<<20) + `"}`
	for _, a := range []answer{{200, "", ""}, {200, "", "null"}, {200, "", "[]"}, {200, "", `"at"`}, {200, "", "42"}, {200, "", "true"},
		{200, "", "<html></html>"}, {200, "", `{"access_token":"at"} {"x":1}`}, {200, "", `{"access_token":"at"}x`}, {200, "", `{"access_token":`},
		{200, "", big}, {201, "", "[]"}, {204, "", ""}} {
		e := endpoint(a)
		tokens, err := redeem(e)
		var ie *IDJAGError
		if !errors.As(err, &ie) || tokens != nil || ie.Code != "invalid_response" || ie.Status != a.status {
			t.Errorf("RedeemIDJAG, %d %.40q: %v %#v", a.status, a.body, tokens, err)
		}
		if jag, err := request(e); !errors.As(err, &ie) || jag != nil || ie.Code != "invalid_response" {
			t.Errorf("RequestIDJAG, %d %.40q: %v %#v", a.status, a.body, jag, err)
		}
	}

	// One JSON object, blanks around it allowed, any 2xx.
	for _, a := range []answer{{200, "", `{"access_token":"at","token_type":"Bearer"}` + "\n"}, {201, "", ` {"access_token":"at"} `}} {
		if tokens, err := redeem(endpoint(a)); err != nil || tokens["access_token"] != "at" {
			t.Errorf("%d %q: %v %v", a.status, a.body, tokens, err)
		}
	}
}

// A refusal's Code is the body's error when that is 1 to 128 RFC 6749 error characters (%x20-21 /
// %x23-5B / %x5D-7E), else server_error; WWW-Authenticate never gives it.
func TestIDJAGErrorCode(t *testing.T) {
	ctx := context.Background()
	var every strings.Builder
	for c := byte(0x20); c <= 0x7e; c++ {
		if c != '"' && c != '\\' {
			every.WriteByte(c)
		}
	}
	long := strings.Repeat("e", 128)
	for _, tc := range []struct {
		status    int
		challenge string
		body      interface{} // JSON-encoded unless a string
		want      string
	}{
		{400, "", map[string]interface{}{"error": "invalid_grant"}, "invalid_grant"},
		{400, "", map[string]interface{}{"error": every.String()}, every.String()},
		{400, "", map[string]interface{}{"error": "a b"}, "a b"},
		{400, "", map[string]interface{}{"error": long}, long},
		{400, "", map[string]interface{}{"error": long + "e"}, "server_error"},
		{400, "", map[string]interface{}{"error": ""}, "server_error"},
		{400, "", map[string]interface{}{"error": `bad"code`}, "server_error"},
		{400, "", map[string]interface{}{"error": `bad\code`}, "server_error"},
		{400, "", map[string]interface{}{"error": "tab\there"}, "server_error"},
		{400, "", map[string]interface{}{"error": "new\nline"}, "server_error"},
		{400, "", map[string]interface{}{"error": "nul\x00"}, "server_error"},
		{400, "", map[string]interface{}{"error": "del\x7f"}, "server_error"},
		{400, "", map[string]interface{}{"error": "nö"}, "server_error"},
		{400, "", map[string]interface{}{"error": " "}, "server_error"},
		{400, "", map[string]interface{}{"error": 5}, "server_error"},
		{400, "", map[string]interface{}{"error": true}, "server_error"},
		{400, "", map[string]interface{}{"error": nil}, "server_error"},
		{400, "", map[string]interface{}{"error": []string{"invalid_grant"}}, "server_error"},
		{400, "", map[string]interface{}{"error": map[string]string{"code": "invalid_grant"}}, "server_error"},
		{400, "", map[string]interface{}{"error_description": "no code"}, "server_error"},
		{401, `DPoP error="invalid_token"`, "", "server_error"},
		{401, `Bearer error="invalid_token"`, "", "server_error"},
		{401, `DPoP error="invalid_token"`, map[string]interface{}{"error": "invalid_client"}, "invalid_client"},
		{302, "", map[string]interface{}{"error": "invalid_grant"}, "invalid_grant"},
		{500, "", "<html>oops</html>", "server_error"},
	} {
		e := newTokenEndpoint(t, func(_ int, w http.ResponseWriter, _ map[string]interface{}) {
			if tc.challenge != "" {
				w.Header().Set("WWW-Authenticate", tc.challenge)
			}
			w.WriteHeader(tc.status)
			if s, ok := tc.body.(string); ok {
				_, _ = io.WriteString(w, s)
			} else {
				_ = json.NewEncoder(w).Encode(tc.body)
			}
		})
		_, err := RedeemIDJAG(ctx, RedeemIDJAGParams{TokenEndpoint: e.URL + "/token", ClientID: "acme", ClientSecret: "s", Assertion: "a.b.c"})
		if ie := idJagErr(t, err); ie.Code != tc.want || ie.Status != tc.status || ie.Err != nil {
			t.Errorf("RedeemIDJAG, %d %v: %q, want %q", tc.status, tc.body, ie.Code, tc.want)
		}
		_, err = RequestIDJAG(ctx, RequestIDJAGParams{TokenEndpoint: e.URL + "/token", ClientID: "app", ClientSecret: "s", IDToken: "id", Audience: "https://rs.example"})
		if ie := idJagErr(t, err); ie.Code != tc.want || ie.Status != tc.status || ie.Err != nil {
			t.Errorf("RequestIDJAG, %d %v: %q, want %q", tc.status, tc.body, ie.Code, tc.want)
		}
	}
}

// Every *IDJAGError from RequestIDJAG and RedeemIDJAG carries the latest valid DPoP-Nonce of the
// call, from any answer, a 2xx too: invalid_response after the nonce retry, or a nonce only a 2xx
// sent.
func TestIDJAGErrorsCarryTheLatestNonce(t *testing.T) {
	ctx := context.Background()
	key, _ := NewIDJAGDPoPKey()
	asks := func(w http.ResponseWriter) {
		w.Header().Set("DPoP-Nonce", "n-1")
		w.WriteHeader(400)
		_, _ = io.WriteString(w, `{"error":"use_dpop_nonce"}`)
	}
	answer := func(status int, nonce, body string) func(w http.ResponseWriter) {
		return func(w http.ResponseWriter) {
			if nonce != "" {
				w.Header().Set("DPoP-Nonce", nonce)
			}
			w.WriteHeader(status)
			_, _ = io.WriteString(w, body)
		}
	}
	for name, tc := range map[string]struct {
		key             *IDJAGDPoPKey
		answers         []func(w http.ResponseWriter)
		redeem, request string // each call's error code; "" is a result
		status          int    // the error's status
		nonce           string
	}{
		"retry, then an object without an ID-JAG":                  {key, []func(http.ResponseWriter){asks, answer(200, "", `{"foo":1}`)}, "", "invalid_response", 0, "n-1"},
		"retry, then an object without an ID-JAG and a new nonce":  {key, []func(http.ResponseWriter){asks, answer(200, "n-2", `{"foo":1}`)}, "", "invalid_response", 0, "n-2"},
		"retry, then an object without an ID-JAG and a bad nonce":  {key, []func(http.ResponseWriter){asks, answer(200, "n 2", `{"foo":1}`)}, "", "invalid_response", 0, "n-1"},
		"retry, then not a JSON object":                            {key, []func(http.ResponseWriter){asks, answer(200, "", `[]`)}, "invalid_response", "invalid_response", 200, "n-1"},
		"retry, then an empty 201 with a new nonce":                {key, []func(http.ResponseWriter){asks, answer(201, "n-2", "")}, "invalid_response", "invalid_response", 201, "n-2"},
		"no key: an object without an ID-JAG, with a nonce":        {nil, []func(http.ResponseWriter){answer(200, "n-3", `{"foo":1}`)}, "", "invalid_response", 0, "n-3"},
		"no key: null, with a nonce":                               {nil, []func(http.ResponseWriter){answer(200, "n-3", "null")}, "invalid_response", "invalid_response", 200, "n-3"},
		"no key: a 302 with a nonce":                               {nil, []func(http.ResponseWriter){answer(302, "n-3", "")}, "server_error", "server_error", 302, "n-3"},
		"retry, then a 500 without a nonce":                        {key, []func(http.ResponseWriter){asks, answer(500, "", "")}, "server_error", "server_error", 500, "n-1"},
		"retry, then trailing data after the object, with a nonce": {key, []func(http.ResponseWriter){asks, answer(200, "n-2", `{"access_token":"at"} x`)}, "invalid_response", "invalid_response", 200, "n-2"},
	} {
		endpoint := func() *tokenEndpoint { // one per call: answers go by the call's own request count
			return newTokenEndpoint(t, func(n int, w http.ResponseWriter, _ map[string]interface{}) {
				tc.answers[min(n, len(tc.answers))-1](w)
			})
		}
		check := func(fn, want string, err error) {
			if want == "" {
				if err != nil {
					t.Errorf("%s, %s: %v", name, fn, err)
				}
				return
			}
			var ie *IDJAGError
			if !errors.As(err, &ie) || ie.Code != want || ie.Status != tc.status || ie.DPoPNonce != tc.nonce {
				t.Errorf("%s, %s: %#v, want %s %d %q", name, fn, err, want, tc.status, tc.nonce)
			}
		}
		_, err := RedeemIDJAG(ctx, RedeemIDJAGParams{TokenEndpoint: endpoint().URL + "/token", ClientID: "acme", ClientSecret: "s", Assertion: "a.b.c", DPoPKey: tc.key})
		check("RedeemIDJAG", tc.redeem, err)
		_, err = RequestIDJAG(ctx, RequestIDJAGParams{TokenEndpoint: endpoint().URL + "/token", ClientID: "app", ClientSecret: "s", IDToken: "id", Audience: "https://rs.example", DPoPKey: tc.key})
		check("RequestIDJAG", tc.request, err)
	}
}

// rawEndpoint is a token endpoint on a raw socket, for what net/http's own server never sends (a
// NUL or other control byte in a header, a broken status line, a body shorter than its
// Content-Length, no answer at all). The n-th request (from 1) gets answers[n-1] as written, the
// last one for any after it: rawClose closes the connection without an answer, and an answer that
// ends in rawHold is written without that suffix and the connection then held open, unanswered,
// until the client closes it (held hears about each). It keeps each request's DPoP proof payload.
type rawEndpoint struct {
	URL    string
	held   chan struct{}
	mu     sync.Mutex
	proofs []map[string]interface{}
}

const (
	rawClose = ""
	rawHold  = "\x00hold"
)

// rawAnswer is an HTTP/1.1 answer with a JSON content type, Connection: close, the header lines
// given and body.
func rawAnswer(status string, headers []string, body string) string {
	var b strings.Builder
	b.WriteString("HTTP/1.1 " + status + "\r\nContent-Type: application/json\r\nConnection: close\r\n")
	for _, h := range headers {
		b.WriteString(h + "\r\n")
	}
	fmt.Fprintf(&b, "Content-Length: %d\r\n\r\n%s", len(body), body)
	return b.String()
}

func newRawEndpoint(t *testing.T, answers ...string) *rawEndpoint {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	e := &rawEndpoint{URL: "http://" + ln.Addr().String() + "/token", held: make(chan struct{}, 16)}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go e.serve(c, answers)
		}
	}()
	return e
}

func (e *rawEndpoint) serve(c net.Conn, answers []string) {
	defer c.Close()
	r := bufio.NewReader(c)
	req, err := http.ReadRequest(r)
	if err != nil {
		return
	}
	_, _ = io.Copy(io.Discard, req.Body)
	_, proof, _ := parseDPoPProof(req.Header.Get("DPoP")) // nil without a valid proof
	e.mu.Lock()
	e.proofs = append(e.proofs, proof)
	n := len(e.proofs)
	e.mu.Unlock()
	answer := answers[min(n, len(answers))-1]
	if answer == rawClose {
		return
	}
	hold := strings.HasSuffix(answer, rawHold)
	_, _ = io.WriteString(c, strings.TrimSuffix(answer, rawHold))
	if hold {
		e.held <- struct{}{}
		_, _ = io.Copy(io.Discard, r) // until the client closes the connection
	}
}

func (e *rawEndpoint) seen() []map[string]interface{} {
	e.mu.Lock()
	defer e.mu.Unlock()
	return append([]map[string]interface{}(nil), e.proofs...)
}

// No readable answer from the token endpoint, on the first request or on the nonce retry, is an
// *IDJAGError temporarily_unavailable: no Status, the call's latest valid nonce, and net/http's
// error as Err (Unwrap), for RequestIDJAG and RedeemIDJAG alike.
func TestIDJAGNoReadableAnswer(t *testing.T) {
	ctx := context.Background()
	key, _ := NewIDJAGDPoPKey()
	asks := rawAnswer("400 Bad Request", []string{"DPoP-Nonce: n-1"}, `{"error":"use_dpop_nonce"}`)
	jag := `{"access_token":"x.y.z","issued_token_type":"` + IDJAGTokenType + `","token_type":"N_A"}`
	cutShort := "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nDPoP-Nonce: n-2\r\nContent-Length: 100\r\nConnection: close\r\n\r\n{\"access_token\":"
	timedOut := func(err error) bool { var ne net.Error; return errors.As(err, &ne) && ne.Timeout() }
	for name, tc := range map[string]struct {
		answers  []string
		client   *http.Client
		requests int
		nonce    string           // the error's DPoPNonce
		cause    func(error) bool // what Err must be
		urlError bool             // net/http's client.Do failed: Err is a *url.Error
		timeout  bool             // the HTTP client's timeout, which net/http also reports as context.DeadlineExceeded
	}{
		"a NUL in DPoP-Nonce": {answers: []string{rawAnswer("400 Bad Request", []string{"DPoP-Nonce: a\x00b"}, `{"error":"use_dpop_nonce"}`)},
			requests: 1, urlError: true},
		"a NUL in the retry answer's DPoP-Nonce": {answers: []string{asks, rawAnswer("200 OK", []string{"DPoP-Nonce: a\x00b"}, jag)},
			requests: 2, nonce: "n-1", urlError: true},
		"a control byte in another header":      {answers: []string{rawAnswer("200 OK", []string{"X-Note: a\x01b"}, jag)}, requests: 1, urlError: true},
		"a DEL in DPoP-Nonce":                   {answers: []string{rawAnswer("400 Bad Request", []string{"DPoP-Nonce: a\x7fb"}, `{"error":"use_dpop_nonce"}`)}, requests: 1, urlError: true},
		"a broken status line":                  {answers: []string{"HTTP/1.1 abc\r\nConnection: close\r\n\r\n"}, requests: 1, urlError: true},
		"closed without an answer":              {answers: []string{rawClose}, requests: 1, urlError: true},
		"closed without an answer to the retry": {answers: []string{asks, rawClose}, requests: 2, nonce: "n-1", urlError: true},
		"a body shorter than its Content-Length": {answers: []string{cutShort}, requests: 1, nonce: "n-2",
			cause: func(err error) bool { return errors.Is(err, io.ErrUnexpectedEOF) }},
		"a retry answer's body shorter than its Content-Length": {answers: []string{asks, cutShort}, requests: 2, nonce: "n-2",
			cause: func(err error) bool { return errors.Is(err, io.ErrUnexpectedEOF) }},
		"a broken chunk": {answers: []string{"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n5\r\n{\"a\":\r\nzz\r\n"},
			requests: 1},
		"a 64 KB header line over the HTTP client's limit": {answers: []string{rawAnswer("200 OK", []string{"X-Long: " + strings.Repeat("a", 65536)}, jag)},
			client: &http.Client{Transport: &http.Transport{MaxResponseHeaderBytes: 16 << 10}}, requests: 1, urlError: true},
		"the HTTP client's timeout": {answers: []string{rawHold}, client: &http.Client{Timeout: 200 * time.Millisecond}, requests: 1, urlError: true,
			cause: timedOut, timeout: true},
		"the HTTP client's timeout in the retry answer's body": {answers: []string{asks, cutShort + rawHold}, client: &http.Client{Timeout: 300 * time.Millisecond},
			requests: 2, nonce: "n-2", cause: timedOut, timeout: true},
	} {
		calls := map[string]func(url string) error{
			"RedeemIDJAG": func(url string) error {
				_, err := RedeemIDJAG(ctx, RedeemIDJAGParams{TokenEndpoint: url, ClientID: "acme", ClientSecret: "s", Assertion: "a.b.c", DPoPKey: key, HTTPClient: tc.client})
				return err
			},
			"RequestIDJAG": func(url string) error {
				_, err := RequestIDJAG(ctx, RequestIDJAGParams{TokenEndpoint: url, ClientID: "app", ClientSecret: "s", IDToken: "id", Audience: "https://rs.example", DPoPKey: key, HTTPClient: tc.client})
				return err
			},
		}
		for _, fn := range []string{"RedeemIDJAG", "RequestIDJAG"} {
			e := newRawEndpoint(t, tc.answers...) // one per call: answers go by the call's own request count
			err := calls[fn](e.URL)
			var ie *IDJAGError
			var ue *url.Error
			switch {
			case !errors.As(err, &ie):
				t.Errorf("%s, %s: not an *IDJAGError: %v", name, fn, err)
			case ie.Code != "temporarily_unavailable" || ie.Status != 0 || ie.DPoPNonce != tc.nonce || ie.Err == nil || errors.Unwrap(err) != ie.Err:
				t.Errorf("%s, %s: %#v", name, fn, ie)
			case tc.urlError && !errors.As(err, &ue):
				t.Errorf("%s, %s: Err is not net/http's *url.Error: %#v", name, fn, ie.Err)
			case tc.cause != nil && !tc.cause(err):
				t.Errorf("%s, %s: Err %#v", name, fn, ie.Err)
			case errors.Is(err, context.Canceled) || (!tc.timeout && errors.Is(err, context.DeadlineExceeded)):
				t.Errorf("%s, %s: reads as a cancellation: %v", name, fn, err)
			case !strings.Contains(err.Error(), "temporarily_unavailable"):
				t.Errorf("%s, %s: %q", name, fn, err.Error())
			}
			seen := e.seen()
			if len(seen) != tc.requests {
				t.Errorf("%s, %s: %d requests, want %d", name, fn, len(seen), tc.requests)
			} else if tc.requests == 2 && (seen[0]["nonce"] != nil || seen[1]["nonce"] != "n-1") {
				t.Errorf("%s, %s: the retry's proof %v", name, fn, seen[1])
			}
		}
	}

	// Not reached at all: the connection is refused.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	refused := "http://" + ln.Addr().String() + "/token"
	_ = ln.Close()
	_, err = RedeemIDJAG(ctx, RedeemIDJAGParams{TokenEndpoint: refused, ClientID: "acme", ClientSecret: "s", Assertion: "a.b.c", DPoPKey: key})
	var ie *IDJAGError
	var ue *url.Error
	if !errors.As(err, &ie) || ie.Code != "temporarily_unavailable" || ie.Status != 0 || ie.DPoPNonce != "" || !errors.As(err, &ue) {
		t.Errorf("RedeemIDJAG, refused: %#v", err)
	}
	_, err = RequestIDJAG(ctx, RequestIDJAGParams{TokenEndpoint: refused, ClientID: "app", ClientSecret: "s", IDToken: "id", Audience: "https://rs.example"})
	if !errors.As(err, &ie) || ie.Code != "temporarily_unavailable" || ie.Status != 0 || !errors.As(err, &ue) {
		t.Errorf("RequestIDJAG, refused: %#v", err)
	}
}

// The caller's own cancellation stays a cancellation: when ctx is cancelled (or its deadline
// passes) while a token endpoint is asked, the error is not an *IDJAGError, and errors.Is finds
// context.Canceled (or context.DeadlineExceeded), and a cancel cause too.
func TestIDJAGCancelledContext(t *testing.T) {
	key, _ := NewIDJAGDPoPKey()
	asks := rawAnswer("400 Bad Request", []string{"DPoP-Nonce: n-1"}, `{"error":"use_dpop_nonce"}`)
	partial := "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 100\r\nConnection: close\r\n\r\n{\"access_token\":" + rawHold
	cause := errors.New("the caller gave up")
	type start func(held <-chan struct{}) (context.Context, func())
	cancelWhenHeld := func(held <-chan struct{}) (context.Context, func()) {
		ctx, cancel := context.WithCancel(context.Background())
		go func() { <-held; cancel() }()
		return ctx, cancel
	}
	for name, tc := range map[string]struct {
		answers  []string
		start    start
		requests int
		want     []error
	}{
		"cancelled while the answer is awaited":           {[]string{rawHold}, cancelWhenHeld, 1, []error{context.Canceled}},
		"cancelled while the retry's answer is awaited":   {[]string{asks, rawHold}, cancelWhenHeld, 2, []error{context.Canceled}},
		"cancelled while the body is read":                {[]string{partial}, cancelWhenHeld, 1, []error{context.Canceled}},
		"cancelled while the retry answer's body is read": {[]string{asks, partial}, cancelWhenHeld, 2, []error{context.Canceled}},
		"cancelled with a cause": {[]string{rawHold}, func(held <-chan struct{}) (context.Context, func()) {
			ctx, cancel := context.WithCancelCause(context.Background())
			go func() { <-held; cancel(cause) }()
			return ctx, func() { cancel(nil) }
		}, 1, []error{context.Canceled, cause}},
		"past its deadline": {[]string{rawHold}, func(<-chan struct{}) (context.Context, func()) {
			return context.WithTimeout(context.Background(), 200*time.Millisecond)
		}, 1, []error{context.DeadlineExceeded}},
		"cancelled before the call": {[]string{asks}, func(<-chan struct{}) (context.Context, func()) {
			ctx, cancel := context.WithCancel(context.Background())
			cancel()
			return ctx, cancel
		}, 0, []error{context.Canceled}},
	} {
		for _, fn := range []string{"RedeemIDJAG", "RequestIDJAG"} {
			e := newRawEndpoint(t, tc.answers...) // one per call: answers go by the call's own request count
			ctx, cancel := tc.start(e.held)
			var err error
			if fn == "RedeemIDJAG" {
				_, err = RedeemIDJAG(ctx, RedeemIDJAGParams{TokenEndpoint: e.URL, ClientID: "acme", ClientSecret: "s", Assertion: "a.b.c", DPoPKey: key})
			} else {
				_, err = RequestIDJAG(ctx, RequestIDJAGParams{TokenEndpoint: e.URL, ClientID: "app", ClientSecret: "s", IDToken: "id", Audience: "https://rs.example", DPoPKey: key})
			}
			cancel()
			var ie *IDJAGError
			if err == nil || errors.As(err, &ie) {
				t.Errorf("%s, %s: %#v", name, fn, err)
			}
			for _, want := range tc.want {
				if !errors.Is(err, want) {
					t.Errorf("%s, %s: errors.Is(%v, %v) is false", name, fn, err, want)
				}
			}
			if n := len(e.seen()); n != tc.requests {
				t.Errorf("%s, %s: %d requests, want %d", name, fn, n, tc.requests)
			}
		}
	}
}

// WWW-Authenticate and DPoP-Nonce are read in linear time: 64 KB headers on a 200 without a key
// and on a 401 with a key and a nonce take well under a second, with the usual result or error.
func TestIDJAGLongHeadersStayFast(t *testing.T) {
	ctx := context.Background()
	key, _ := NewIDJAGDPoPKey()
	long := strings.Repeat("a", 65536)
	jag := `{"access_token":"x.y.z","issued_token_type":"` + IDJAGTokenType + `","token_type":"N_A"}`
	for name, tc := range map[string]struct {
		challenge, nonce string
		asks             bool // the 401 asks for a nonce of valid syntax: one retry
		badNonce         bool // the nonce is not valid syntax: not on the error
	}{
		"a 65536-character quoted parameter":        {challenge: `DPoP error_description="` + long + `"`, nonce: "n-1"},
		"DPoP and 30000 times a,":                   {challenge: "DPoP " + strings.Repeat("a,", 30000), nonce: "n-1"},
		"an unterminated quoted string":             {challenge: `DPoP error="` + long, nonce: "n-1"},
		"65536 backslashes in a quoted string":      {challenge: `DPoP error="` + strings.Repeat(`\`, 65536) + `"`, nonce: "n-1"},
		"32768 empty items":                         {challenge: strings.Repeat(", ", 32768) + "DPoP", nonce: "n-1"},
		"a 65536-character scheme":                  {challenge: long + ` error="use_dpop_nonce"`, nonce: "n-1"},
		"9000 parameters, then the ask":             {challenge: "DPoP " + strings.Repeat(`a="b", `, 9000) + `error="use_dpop_nonce"`, nonce: "n-1", asks: true},
		"a 65536-character nonce":                   {challenge: `DPoP error="use_dpop_nonce"`, nonce: long, asks: true},
		"a 65536-character nonce ending in a quote": {challenge: `DPoP error="use_dpop_nonce"`, nonce: long[1:] + `"`, badNonce: true},
	} {
		var slowest time.Duration
		timed := func(call func() error) error {
			start := time.Now()
			err := call()
			if d := time.Since(start); d > slowest {
				slowest = d
			}
			return err
		}
		answer := func(status int) *tokenEndpoint {
			return newTokenEndpoint(t, func(_ int, w http.ResponseWriter, _ map[string]interface{}) {
				w.Header().Set("WWW-Authenticate", tc.challenge)
				w.Header().Set("DPoP-Nonce", tc.nonce)
				w.WriteHeader(status)
				if status == 200 {
					_, _ = io.WriteString(w, jag)
				}
			})
		}

		// A 200 without a key: the usual result.
		ok := answer(200)
		if err := timed(func() error {
			tokens, err := RedeemIDJAG(ctx, RedeemIDJAGParams{TokenEndpoint: ok.URL + "/token", ClientID: "acme", ClientSecret: "s", Assertion: "a.b.c"})
			if err == nil && tokens["token_type"] != "N_A" {
				return fmt.Errorf("tokens %v", tokens)
			}
			return err
		}); err != nil {
			t.Errorf("%s, 200: RedeemIDJAG %v", name, err)
		}
		if err := timed(func() error {
			_, err := RequestIDJAG(ctx, RequestIDJAGParams{TokenEndpoint: ok.URL + "/token", ClientID: "app", ClientSecret: "s", IDToken: "id", Audience: "https://rs.example"})
			return err
		}); err != nil {
			t.Errorf("%s, 200: RequestIDJAG %v", name, err)
		}

		// A 401 with a key and a nonce: the *IDJAGError, after one retry when it asks.
		refused := answer(401)
		want, requests := tc.nonce, 1
		if tc.badNonce {
			want = ""
		}
		if tc.asks {
			requests = 2
		}
		for _, call := range []func() error{
			func() error {
				_, err := RedeemIDJAG(ctx, RedeemIDJAGParams{TokenEndpoint: refused.URL + "/token", ClientID: "acme", ClientSecret: "s", Assertion: "a.b.c", DPoPKey: key})
				return err
			},
			func() error {
				_, err := RequestIDJAG(ctx, RequestIDJAGParams{TokenEndpoint: refused.URL + "/token", ClientID: "app", ClientSecret: "s", IDToken: "id", Audience: "https://rs.example", DPoPKey: key})
				return err
			},
		} {
			before := len(refused.seen())
			err := timed(call)
			var ie *IDJAGError
			if !errors.As(err, &ie) || ie.Status != 401 || ie.DPoPNonce != want || len(refused.seen())-before != requests {
				t.Errorf("%s, 401: %d requests, %.200v", name, len(refused.seen())-before, err)
			}
		}
		if slowest > time.Second {
			t.Errorf("%s: %v for one call", name, slowest)
		}
	}
}

// The header parsers alone, at 512 KiB: linear time keeps them in milliseconds, where a
// quadratic one would take many seconds.
func TestXAAHeaderParsersAreLinear(t *testing.T) {
	const size = 1 << 19
	start := time.Now()
	for header, want := range map[string]bool{
		`DPoP error_description="` + strings.Repeat("a", size) + `"`:                false,
		"DPoP " + strings.Repeat("a,", size/2):                                      false,
		`DPoP error="` + strings.Repeat(`\`, size):                                  false,
		strings.Repeat(`, `, size/2) + `DPoP error="use_dpop_nonce"`:                true,
		"DPoP " + strings.Repeat(`a="b", `, size/8) + `error=use_dpop_nonce`:        true,
		`DPoP x="` + strings.Repeat(`\"`, size/2) + `", error="use_dpop_nonce"`:     true,
		`DPoP error="` + strings.Repeat(`\a`, size/2) + `"`:                         false,
		`DPoP error="use_dpop_nonce` + strings.Repeat(`\`, size):                    false,
		strings.Repeat(`DPoP error="a", `, size/16) + `DPoP error="use_dpop_nonce"`: true,
	} {
		if got := xaaNonceChallenge(http.Header{"Www-Authenticate": {header}}); got != want {
			t.Errorf("%.40q...: %v", header, got)
		}
	}
	nonce := strings.Repeat("n", size)
	if xaaDPoPNonce(http.Header{"Dpop-Nonce": {nonce}}) != nonce || xaaDPoPNonce(http.Header{"Dpop-Nonce": {nonce + " "}}) != "" {
		t.Error("a 512 KiB nonce")
	}
	if xaaDPoPNonce(http.Header{"Dpop-Nonce": {strings.Repeat("n-1, ", size/5) + "n-1"}}) != "n-1" ||
		xaaDPoPNonce(http.Header{"Dpop-Nonce": {strings.Repeat("n-1, ", size/5) + "n-2"}}) != "" {
		t.Error("a 512 KiB joined nonce")
	}
	if d := time.Since(start); d > time.Second {
		t.Fatalf("%v for 6.5 MiB of headers", d)
	}
}

// tokenEndpoint is a fake token endpoint: it keeps each request's body, Authorization header
// and DPoP proof payload, and answers the n-th (from 1) with answer.
type tokenEndpoint struct {
	*httptest.Server
	mu    sync.Mutex
	calls []tokenCall
}

type tokenCall struct {
	body, auth string
	proof      map[string]interface{} // nil without a DPoP header
}

func newTokenEndpoint(t *testing.T, answer func(n int, w http.ResponseWriter, proof map[string]interface{})) *tokenEndpoint {
	e := &tokenEndpoint{}
	e.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var proof map[string]interface{}
		if p := r.Header.Get("DPoP"); p != "" {
			var err error
			if _, proof, err = parseDPoPProof(p); err != nil {
				t.Error(err)
			}
		}
		e.mu.Lock()
		e.calls = append(e.calls, tokenCall{string(body), r.Header.Get("Authorization"), proof})
		n := len(e.calls)
		e.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		answer(n, w, proof)
	}))
	t.Cleanup(e.Close)
	return e
}

func (e *tokenEndpoint) seen() []tokenCall {
	e.mu.Lock()
	defer e.mu.Unlock()
	return append([]tokenCall(nil), e.calls...)
}

func idJagErr(t *testing.T, err error) *IDJAGError {
	t.Helper()
	var e *IDJAGError
	if !errors.As(err, &e) {
		t.Fatalf("not an *IDJAGError: %v", err)
	}
	return e
}

func TestIDJAGDPoPNonceRetry(t *testing.T) {
	ctx := context.Background()
	key, _ := NewIDJAGDPoPKey()
	enc := func(v interface{}) string { b, _ := json.Marshal(v); return base64.RawURLEncoding.EncodeToString(b) }

	// RequestIDJAG: 400 use_dpop_nonce with a DPoP-Nonce (RFC 9449 section 8), then the ID-JAG for
	// a proof with that nonce.
	idp := newTokenEndpoint(t, func(n int, w http.ResponseWriter, proof map[string]interface{}) {
		if proof["nonce"] != "n-1" {
			w.Header().Set("DPoP-Nonce", "n-1")
			w.WriteHeader(400)
			_, _ = w.Write([]byte(`{"error":"use_dpop_nonce","error_description":"Authorization server requires nonce in DPoP proof"}`))
			return
		}
		jag := enc(map[string]string{"typ": "oauth-id-jag+jwt", "alg": "RS256"}) + "." + enc(map[string]interface{}{"cnf": map[string]string{"jkt": key.Thumbprint}}) + ".sig"
		_ = json.NewEncoder(w).Encode(map[string]string{"access_token": jag, "issued_token_type": IDJAGTokenType, "token_type": "N_A"})
	})
	jag, err := RequestIDJAG(ctx, RequestIDJAGParams{TokenEndpoint: idp.URL + "/token?x=1", ClientID: "tqapp_test", ClientSecret: "tqs_test", IDToken: "idtoken:ada", Audience: "https://rs.example", DPoPKey: key})
	if err != nil || !jag.DPoPBound {
		t.Fatal(jag, err)
	}
	calls := idp.seen()
	if len(calls) != 2 {
		t.Fatalf("%d requests, want 2", len(calls))
	}
	first, second := calls[0], calls[1]
	if first.proof["nonce"] != nil || second.proof["nonce"] != "n-1" || first.proof["jti"] == second.proof["jti"] || second.proof["iat"] == nil {
		t.Fatal(first.proof, second.proof)
	}
	for _, c := range calls {
		if c.proof["htm"] != "POST" || c.proof["htu"] != idp.URL+"/token" {
			t.Fatal(c.proof)
		}
	}
	if !strings.Contains(first.body, "subject_token=idtoken%3Aada") || second.body != first.body || !strings.HasPrefix(first.auth, "Basic ") || second.auth != first.auth {
		t.Fatalf("the retry changed the request:\n%+v\n%+v", first, second)
	}

	// RedeemIDJAG: a 401 that asks with WWW-Authenticate (no JSON error), client_id in the form.
	as := newTokenEndpoint(t, func(n int, w http.ResponseWriter, proof map[string]interface{}) {
		if proof["nonce"] != "n-2" {
			w.Header().Set("DPoP-Nonce", "n-2")
			w.Header().Set("WWW-Authenticate", `DPoP algs="ES256", error="use_dpop_nonce", error_description="Resource server requires nonce in DPoP proof"`)
			w.WriteHeader(401)
			return
		}
		_, _ = w.Write([]byte(`{"access_token":"at","token_type":"DPoP"}`))
	})
	tokens, err := RedeemIDJAG(ctx, RedeemIDJAGParams{TokenEndpoint: as.URL + "/token", ClientID: "acme-at-rs", Assertion: jag.Assertion, DPoPKey: key})
	if err != nil || tokens["token_type"] != "DPoP" {
		t.Fatal(tokens, err)
	}
	calls = as.seen()
	if len(calls) != 2 || calls[1].proof["nonce"] != "n-2" || calls[0].proof["jti"] == calls[1].proof["jti"] ||
		!strings.Contains(calls[0].body, "client_id=acme-at-rs") || calls[1].body != calls[0].body || calls[1].auth != "" {
		t.Fatalf("%+v", calls)
	}
}

func TestIDJAGDPoPNonceRetryOnlyOnce(t *testing.T) {
	ctx := context.Background()
	key, _ := NewIDJAGDPoPKey()
	asksEveryTime := func(n int, w http.ResponseWriter, _ map[string]interface{}) {
		w.Header().Set("DPoP-Nonce", fmt.Sprintf("n-%d", n))
		w.WriteHeader(400)
		_, _ = w.Write([]byte(`{"error":"use_dpop_nonce"}`))
	}
	redeem := func(e *tokenEndpoint, key *IDJAGDPoPKey) error {
		_, err := RedeemIDJAG(ctx, RedeemIDJAGParams{TokenEndpoint: e.URL + "/token", ClientID: "acme", ClientSecret: "s", Assertion: "a.b.c", DPoPKey: key})
		return err
	}

	// It asks again after the retry: no second retry; the error has the latest nonce.
	e := newTokenEndpoint(t, asksEveryTime)
	if err := idJagErr(t, redeem(e, key)); len(e.seen()) != 2 || err.Code != "use_dpop_nonce" || err.Status != 400 || err.DPoPNonce != "n-2" || e.seen()[1].proof["nonce"] != "n-1" {
		t.Fatal(len(e.seen()), err)
	}
	_, err := RequestIDJAG(ctx, RequestIDJAGParams{TokenEndpoint: e.URL + "/token", ClientID: "app", ClientSecret: "s", IDToken: "id", Audience: "https://rs.example", DPoPKey: key})
	if err := idJagErr(t, err); len(e.seen()) != 4 || err.DPoPNonce != "n-4" || e.seen()[3].proof["nonce"] != "n-3" {
		t.Fatal(len(e.seen()), err)
	}

	// No key: one request with no DPoP header, no retry; the error still has the nonce.
	e = newTokenEndpoint(t, asksEveryTime)
	if err := idJagErr(t, redeem(e, nil)); len(e.seen()) != 1 || e.seen()[0].proof != nil || err.Code != "use_dpop_nonce" || err.DPoPNonce != "n-1" {
		t.Fatal(len(e.seen()), err)
	}
	_, err = RequestIDJAG(ctx, RequestIDJAGParams{TokenEndpoint: e.URL + "/token", ClientID: "app", ClientSecret: "s", IDToken: "id", Audience: "https://rs.example"})
	if err := idJagErr(t, err); len(e.seen()) != 2 || e.seen()[1].proof != nil || err.DPoPNonce != "n-2" {
		t.Fatal(len(e.seen()), err)
	}

	// The retry fails otherwise: its error, with the nonce the call used.
	e = newTokenEndpoint(t, func(n int, w http.ResponseWriter, _ map[string]interface{}) {
		if n == 1 {
			asksEveryTime(n, w, nil)
			return
		}
		w.WriteHeader(400)
		_, _ = w.Write([]byte(`{"error":"invalid_grant","error_description":"ID-JAG already used"}`))
	})
	if err := idJagErr(t, redeem(e, key)); len(e.seen()) != 2 || err.Code != "invalid_grant" || err.Message != "ID-JAG already used" || err.DPoPNonce != "n-1" {
		t.Fatal(len(e.seen()), err)
	}

	// Not a nonce request: one request each, a nonce sent along is still on the error.
	for name, answer := range map[string]func(w http.ResponseWriter){
		"use_dpop_nonce without DPoP-Nonce": func(w http.ResponseWriter) {
			w.WriteHeader(400)
			_, _ = w.Write([]byte(`{"error":"use_dpop_nonce"}`))
		},
		"another error": func(w http.ResponseWriter) {
			w.Header().Set("DPoP-Nonce", "n-9")
			w.WriteHeader(400)
			_, _ = w.Write([]byte(`{"error":"invalid_client"}`))
		},
		"a 403": func(w http.ResponseWriter) {
			w.Header().Set("DPoP-Nonce", "n-9")
			w.WriteHeader(403)
			_, _ = w.Write([]byte(`{"error":"use_dpop_nonce"}`))
		},
		"use_dpop_nonce in another scheme's challenge": func(w http.ResponseWriter) {
			w.Header().Set("DPoP-Nonce", "n-9")
			w.Header().Set("WWW-Authenticate", `Bearer error="use_dpop_nonce", DPoP algs="ES256"`)
			w.WriteHeader(401)
		},
	} {
		e := newTokenEndpoint(t, func(_ int, w http.ResponseWriter, _ map[string]interface{}) { answer(w) })
		err := idJagErr(t, redeem(e, key))
		want := "n-9"
		if name == "use_dpop_nonce without DPoP-Nonce" {
			want = ""
		}
		if len(e.seen()) != 1 || err.DPoPNonce != want {
			t.Errorf("%s: %d requests, %+v", name, len(e.seen()), err)
		}
	}
}

func TestXAANonceChallenge(t *testing.T) {
	for header, want := range map[string]bool{
		`DPoP error="use_dpop_nonce"`: true,
		`dpop error=use_dpop_nonce`:   true,
		`DPoP algs="ES256 PS256", error="use_dpop_nonce", error_description="x, y"`: true,
		`Bearer realm="a, b", DPoP error = "use_dpop_nonce"`:                        true,
		`Bearer error="use_dpop_nonce", DPoP algs="ES256"`:                          false,
		`DPoP error="invalid_dpop_proof"`:                                           false,
		`DPoP error_description="use_dpop_nonce"`:                                   false,
		`Basic realm="use_dpop_nonce"`:                                              false,
		`DPoP`:                                                                      false,
		// A quoted value has its quoted-pairs undone and needs its closing quote.
		`DPoP error="use\_dpop\_nonce"`:  true,
		`DPoP error="\u\s\e_dpop_nonce"`: true,
		`DPoP error="use_dpop_nonce`:     false,
		`DPoP error="use_dpop_nonce\"`:   false,
		`DPoP error="use_dpop_nonce\\"`:  false,
		`DPoP error="use_dpop_nonce\`:    false,
		`DPoP error=use_dpop_nonce"`:     false,
		`DPoP error="use_dpop_nonce" x`:  false,
		`DPoP error="use_dpop_nonce"x`:   false,
		`DPoP error=use_dpop_nonce x`:    false,
		`DPoP error=""use_dpop_nonce""`:  false,
		`DPoP error="use_dpop_nonce"  `:  true,
		`DPoP error=`:                    false,
		`DPoP error=""`:                  false,
		// Commas in a quoted string, after an escaped quote too, do not split.
		`DPoP realm="a\", error=use_dpop_nonce"`:          false,
		`DPoP realm="a\\", error=use_dpop_nonce`:          true,
		`Bearer realm="x, DPoP error=\"use_dpop_nonce\""`: false,
		// Only the DPoP challenge's own error parameter, exactly use_dpop_nonce; names in any case.
		`DPoP error="USE_DPOP_NONCE"`:                      false,
		`DPoP error="use_dpop_nonce "`:                     false,
		`DPOP ERROR="use_dpop_nonce"`:                      true,
		`dPoP Error=use_dpop_nonce`:                        true,
		`DPoP algs="ES256", Bearer error="use_dpop_nonce"`: false,
		`DPoP x=use_dpop_nonce`:                            false,
		`DPoPx error=use_dpop_nonce`:                       false,
		`NotDPoP error=use_dpop_nonce`:                     false,
	} {
		if got := xaaNonceChallenge(http.Header{"Www-Authenticate": {header}}); got != want {
			t.Errorf("%s: %v", header, got)
		}
	}
	if !xaaNonceChallenge(http.Header{"Www-Authenticate": {`Bearer realm="x"`, `DPoP error="use_dpop_nonce"`}}) || xaaNonceChallenge(http.Header{}) {
		t.Fatal("two WWW-Authenticate lines")
	}
	// Several lines are one list (RFC 9110 section 5.3): a parameter on the next line belongs to
	// the challenge before it, and a quoted string left open runs on.
	for lines, want := range map[[2]string]bool{
		{`DPoP algs="ES256"`, `error="use_dpop_nonce"`}:          true,
		{`Bearer realm="x"`, `error="use_dpop_nonce"`}:           false,
		{`Bearer realm="x`, `DPoP error="use_dpop_nonce"`}:       false,
		{`DPoP error="use_dpop_nonce"`, `Bearer error="other"`}:  true,
		{`Bearer error="use_dpop_nonce"`, `DPoP algs="ES256"`}:   false,
		{`DPoP algs="ES256", error="x"`, `error=use_dpop_nonce`}: true,
	} {
		if got := xaaNonceChallenge(http.Header{"Www-Authenticate": lines[:]}); got != want {
			t.Errorf("%q: %v", lines, got)
		}
	}
}

func TestIDJAGDPoPKeyKeepsItsPrivateHalf(t *testing.T) {
	key, _ := NewIDJAGDPoPKey()
	d, err := key.PrivateKey().Bytes()
	if err != nil || len(d) != 32 {
		t.Fatal(err)
	}
	secrets := []string{new(big.Int).SetBytes(d).String(), base64.RawURLEncoding.EncodeToString(d), base64.StdEncoding.EncodeToString(d), hex.EncodeToString(d), fmt.Sprint(d)}
	var outputs []string
	for _, v := range []interface{}{key, *key, RequestIDJAGParams{DPoPKey: key}, RedeemIDJAGParams{DPoPKey: key}} {
		b, err := json.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		var logs bytes.Buffer
		slog.New(slog.NewJSONHandler(&logs, nil)).Info("id-jag", "dpopKey", v)
		slog.New(slog.NewTextHandler(&logs, nil)).Info("id-jag", "dpopKey", v)
		outputs = append(outputs, string(b), logs.String(), fmt.Sprintf("%v", v), fmt.Sprintf("%+v", v), fmt.Sprintf("%#v", v), fmt.Sprintf("%s", v))
	}
	for _, out := range outputs {
		for _, s := range secrets {
			if strings.Contains(out, s) {
				t.Fatalf("the private key shows in %s", out)
			}
		}
	}
	if !strings.Contains(outputs[0], key.Thumbprint) || !strings.Contains(outputs[0], `"PublicJWK"`) {
		t.Fatal(outputs[0])
	}
	// PrivateKey gives a copy; NewIDJAGDPoPKeyFrom takes it back.
	back, err := NewIDJAGDPoPKeyFrom(key.PrivateKey())
	if err != nil || back.Thumbprint != key.Thumbprint || key.PrivateKey() == key.PrivateKey() || !key.PrivateKey().Equal(back.PrivateKey()) {
		t.Fatal(back, err)
	}
	proof, err := IDJAGDPoPProof(back, "https://as.example/token")
	if err != nil {
		t.Fatal(err)
	}
	if header, _ := dpopProof(t, proof); JWKThumbprint(header["jwk"].(map[string]interface{})) != key.Thumbprint {
		t.Fatal(header)
	}
}

func TestIDJAGDPoPKeyMisuseIsAnError(t *testing.T) {
	ctx := context.Background()
	e := newTokenEndpoint(t, func(int, http.ResponseWriter, map[string]interface{}) {})
	good, _ := NewIDJAGDPoPKey()
	p384, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	p521, _ := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	var ce *ConfigError
	for name, priv := range map[string]*ecdsa.PrivateKey{
		"nil": nil, "P-384": p384, "P-521": p521, "zero": {},
		"P-256 without scalar or point": {PublicKey: ecdsa.PublicKey{Curve: elliptic.P256()}},
	} {
		if key, err := NewIDJAGDPoPKeyFrom(priv); key != nil || !errors.As(err, &ce) {
			t.Errorf("%s: %v %v", name, key, err)
		}
	}
	for name, key := range map[string]*IDJAGDPoPKey{"nil": nil, "zero": {}, "public half only": {PublicJWK: good.PublicJWK, Thumbprint: good.Thumbprint}} {
		if _, err := IDJAGDPoPProof(key, "https://as.example/token"); !errors.As(err, &ce) {
			t.Errorf("%s: IDJAGDPoPProof %v", name, err)
		}
		if _, err := IDJAGDPoPProofWith(key, "GET", "https://as.example/api", IDJAGDPoPProofOptions{AccessToken: "at"}); !errors.As(err, &ce) {
			t.Errorf("%s: IDJAGDPoPProofWith %v", name, err)
		}
		if key.PrivateKey() != nil {
			t.Errorf("%s: a private key", name)
		}
		if key == nil {
			continue // no DPoPKey: no DPoP
		}
		if _, err := RequestIDJAG(ctx, RequestIDJAGParams{Issuer: e.URL, ClientID: "app", ClientSecret: "s", IDToken: "id", Audience: "https://rs.example", DPoPKey: key}); !errors.As(err, &ce) {
			t.Errorf("%s: RequestIDJAG %v", name, err)
		}
		if _, err := RedeemIDJAG(ctx, RedeemIDJAGParams{TokenEndpoint: e.URL + "/token", ClientID: "acme", Assertion: "a.b.c", DPoPKey: key}); !errors.As(err, &ce) {
			t.Errorf("%s: RedeemIDJAG %v", name, err)
		}
	}
	if n := len(e.seen()); n != 0 {
		t.Fatalf("%d requests with an unusable key", n)
	}
}

func fetchBody(t *testing.T, u string) []byte {
	t.Helper()
	resp, err := http.Get(u)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return b
}

func cardCode(err error) string {
	var e *AgentCardError
	if errors.As(err, &e) {
		return e.Code
	}
	return ""
}

func TestAgentCards(t *testing.T) {
	api := startFakeAPI(t)
	ctx := context.Background()
	u := api.baseURL + "/.well-known/agent-card.json"
	card := fetchBody(t, u)
	got, err := VerifyAgentCard(ctx, card, VerifyAgentCardOptions{CardURL: u})
	if err != nil || *got != (AgentCardVerification{KID: "a2a-1", Alg: "ES256", KeySource: "jku"}) {
		t.Fatal(got, err)
	}
	if _, err := VerifyAgentCard(ctx, fetchBody(t, u+"?tamper=1"), VerifyAgentCardOptions{CardURL: u}); cardCode(err) != "invalid_signature" {
		t.Fatal(err)
	}
	if _, err := VerifyAgentCard(ctx, card, VerifyAgentCardOptions{CardURL: "https://agent.example/.well-known/agent-card.json"}); cardCode(err) != "untrusted_key" {
		t.Fatal(err)
	}
	if _, err := VerifyAgentCard(ctx, []byte(`{"name":"x"}`), VerifyAgentCardOptions{}); cardCode(err) != "unsigned" {
		t.Fatal(err)
	}

	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	signed, err := SignAgentCard([]byte(`{"name":"Mine","url":"https://mine.example/a2a","skills":[]}`), priv, "k1", "")
	if err != nil {
		t.Fatal(err)
	}
	jwk := map[string]interface{}{"kty": "OKP", "crv": "Ed25519", "x": base64.RawURLEncoding.EncodeToString(pub), "kid": "k1"}
	if v, err := VerifyAgentCard(ctx, signed, VerifyAgentCardOptions{Keys: []map[string]interface{}{jwk}}); err != nil || v.Alg != "EdDSA" || v.KeySource != "keys" {
		t.Fatal(v, err)
	}
	evil := strings.Replace(string(signed), "https://mine.example/a2a", "https://evil.example/a2a", 1)
	if _, err := VerifyAgentCard(ctx, []byte(evil), VerifyAgentCardOptions{Keys: []map[string]interface{}{jwk}}); cardCode(err) != "invalid_signature" {
		t.Fatal(err)
	}

	d := json.NewDecoder(strings.NewReader(`{"€":"Euro","\r":"CR","😀":"smile","1":"one","a":[1e21,1e-7,0.5,-0,"tab\there",1e-5,100.0]}`))
	d.UseNumber()
	var x interface{}
	_ = d.Decode(&x)
	s, err := CanonicalJSON(x)
	if want := `{"\r":"CR","1":"one","a":[1e+21,1e-7,0.5,0,"tab\there",0.00001,100],"€":"Euro","😀":"smile"}`; err != nil || s != want {
		t.Fatalf("%s\n%s", s, want)
	}
}

// opaqueSigner hides the key's type, the way a KMS, HSM or PKCS#11 signer does.
type opaqueSigner struct{ crypto.Signer }

func TestSignAgentCardWithAnySigner(t *testing.T) {
	ctx := context.Background()
	card := []byte(`{"name":"Mine","url":"https://mine.example/a2a","skills":[]}`)
	ec, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	rs, _ := rsa.GenerateKey(rand.Reader, 2048)
	ecJWK := ecPublicJWK(&ec.PublicKey)
	ecJWK["kid"] = "k1"
	rsaJWK := map[string]interface{}{"kty": "RSA", "kid": "k1", "n": base64.RawURLEncoding.EncodeToString(rs.N.Bytes()), "e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(rs.E)).Bytes())}
	for _, c := range []struct {
		alg string
		key crypto.Signer
		jwk map[string]interface{}
	}{{"ES256", ec, ecJWK}, {"ES256", opaqueSigner{ec}, ecJWK}, {"RS256", opaqueSigner{rs}, rsaJWK}} {
		signed, err := SignAgentCard(card, c.key, "k1", "")
		if err != nil {
			t.Fatalf("%T: %v", c.key, err)
		}
		if v, err := VerifyAgentCard(ctx, signed, VerifyAgentCardOptions{Keys: []map[string]interface{}{c.jwk}}); err != nil || v.Alg != c.alg {
			t.Fatalf("%T: %v %v", c.key, v, err)
		}
	}
	p384, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if _, err := SignAgentCard(card, p384, "k1", ""); cardCode(err) != "malformed" {
		t.Fatalf("a P-384 key is not ES256, got %v", err)
	}
}
