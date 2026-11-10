package touchque

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"math/big"
	"net/http"
	"strings"
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
