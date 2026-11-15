package touchque

import (
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
	"net/http"
	"net/http/httptest"
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
	// "" is POST; no options, no ath and no nonce.
	proof, _ = IDJAGDPoPProofWith(key, "", "https://as.example/token", IDJAGDPoPProofOptions{})
	if _, post := dpopProof(t, proof); len(post) != 4 || post["htm"] != "POST" {
		t.Fatal(post)
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
		// "." and ".." segments resolved, also written %2e.
		"https://as.example/a/./b/../c": "https://as.example/a/c",
		"https://as.example/a/%2e%2E/c": "https://as.example/c",
		"https://as.example/a/b/..":     "https://as.example/a/",
		"https://as.example/a/b/.":      "https://as.example/a/b/",
		"https://as.example/..":         "https://as.example/",
	} {
		proof, err := IDJAGDPoPProofWith(key, "GET", target, IDJAGDPoPProofOptions{})
		if err != nil {
			t.Fatalf("%s: %v", target, err)
		}
		if _, payload := dpopProof(t, proof); payload["htu"] != want {
			t.Errorf("%s: htu %v, want %s", target, payload["htu"], want)
		}
	}
	var ce *ConfigError
	for _, target := range []string{"", "/token", "as.example/token", "https:as.example/token", "https://as.example:99999/t", "https://as.example/a%zz"} {
		if proof, err := IDJAGDPoPProof(key, target); !errors.As(err, &ce) {
			t.Errorf("%q: %s %v", target, proof, err)
		}
	}
}

func TestIDJAGDPoPProofMethod(t *testing.T) {
	key, _ := NewIDJAGDPoPKey()
	// Trimmed and uppercased; nothing left is POST.
	for method, want := range map[string]string{
		"": "POST", "   ": "POST", "\t\r\n": "POST", "\u00a0": "POST",
		"get": "GET", " get ": "GET", "\tPatch\n": "PATCH", "DELETE": "DELETE",
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
	// to ASCII (U+017F long s to S, U+0131 dotless i to I).
	var ce *ConfigError
	for _, method := range []string{"GET /x", "GE T", "GET\r\nX-Injected: 1", `PO"ST`, "GET(", "GET,POST", "GET;", "GET:", "[GET]", "{}",
		"a/b", `a\b`, "a=b", "a@b", "a?b", "p\u00f6st", "po\u017ft", "g\u0131t", "\u0413\u0415\u0422", "GET\x00", "\x7f"} {
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
		"every NQCHAR":             {first: []string{every.String()}, retried: every.String(), want: every.String()},
		"8192 characters":          {first: []string{long}, retry: []string{"n-2"}, retried: long, want: "n-2"},
		"twice, the same value":    {first: []string{"n-1", "n-1"}, retry: []string{"n-2", "n-2"}, retried: "n-1", want: "n-2"},
		"missing":                  {},
		"empty":                    {first: []string{""}},
		"twice, different values":  {first: []string{"n-1", "n-2"}},
		"a space":                  {first: []string{"n 1"}},
		"a tab":                    {first: []string{"n\t1"}},
		"a double quote":           {first: []string{`n"1`}},
		"quoted":                   {first: []string{`"n-1"`}},
		"a backslash":              {first: []string{`n\1`}},
		"not ASCII":                {first: []string{"n\u00f6nce"}},
		"retry answer, none":       {first: []string{"n-1"}, retried: "n-1", want: "n-1"},
		"retry answer, invalid":    {first: []string{"n-1"}, retry: []string{"n 2"}, retried: "n-1", want: "n-1"},
		"retry answer, two values": {first: []string{"n-1"}, retry: []string{"n-2", "n-3"}, retried: "n-1", want: "n-1"},
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
		`DPoP error_description="` + strings.Repeat("a", size) + `"`:         false,
		"DPoP " + strings.Repeat("a,", size/2):                               false,
		`DPoP error="` + strings.Repeat(`\`, size):                           false,
		strings.Repeat(`, `, size/2) + `DPoP error="use_dpop_nonce"`:         true,
		"DPoP " + strings.Repeat(`a="b", `, size/8) + `error=use_dpop_nonce`: true,
	} {
		if got := xaaNonceChallenge(http.Header{"Www-Authenticate": {header}}); got != want {
			t.Errorf("%.40q...: %v", header, got)
		}
	}
	nonce := strings.Repeat("n", size)
	if xaaDPoPNonce(http.Header{"Dpop-Nonce": {nonce}}) != nonce || xaaDPoPNonce(http.Header{"Dpop-Nonce": {nonce + " "}}) != "" {
		t.Error("a 512 KiB nonce")
	}
	if d := time.Since(start); d > time.Second {
		t.Fatalf("%v for 3.5 MiB of headers", d)
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
	} {
		if got := xaaNonceChallenge(http.Header{"Www-Authenticate": {header}}); got != want {
			t.Errorf("%s: %v", header, got)
		}
	}
	if !xaaNonceChallenge(http.Header{"Www-Authenticate": {`Bearer realm="x"`, `DPoP error="use_dpop_nonce"`}}) || xaaNonceChallenge(http.Header{}) {
		t.Fatal("two WWW-Authenticate lines")
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
