package touchque

// A2A agent card signatures (A2A 1.0 §8.4): before your agent trusts another
// agent's card (its name, URL, skills), check that whoever controls its keys
// signed exactly this card. Each entry of `signatures` is a JWS (RFC 7515)
// over the card in RFC 8785 canonical form without `signatures`; the protected
// header names alg, kid and optionally jku (where the keys are).
//
//	v, err := touchque.VerifyAgentCard(ctx, cardJSON, touchque.VerifyAgentCardOptions{CardURL: "https://agent.example/.well-known/agent-card.json"})
//
// Keys come from Keys (a JWKS you trust) or from the header's jku, but jku is
// only followed on the card's own host (or a host in TrustedJKUHosts): a card
// that points at keys on a host of its choosing proves nothing. Signers must
// leave out fields at their default values (A2A §8.4.1); the card is checked
// as received. Pass the card as the raw JSON you received.

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
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math"
	"math/big"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf16"
)

// AgentCardError: Code is unsigned, malformed, untrusted_key, invalid_signature or keys_unavailable.
type AgentCardError struct {
	Code    string
	Message string
}

func (e *AgentCardError) Error() string { return fmt.Sprintf("touchque: %s (%s)", e.Message, e.Code) }

// VerifyAgentCardOptions: where the card came from, keys you trust, other hosts a jku may name.
type VerifyAgentCardOptions struct {
	CardURL         string
	Keys            []map[string]interface{}
	TrustedJKUHosts []string
	HTTPClient      *http.Client
}

// AgentCardVerification is the signature that verified; KeySource is "keys" or "jku".
type AgentCardVerification struct {
	KID       string
	Alg       string
	KeySource string
}

// esNumber writes a number as ECMAScript's Number::toString does (RFC 8785 §3.2.2.3).
func esNumber(f float64) (string, error) {
	if math.IsNaN(f) || math.IsInf(f, 0) {
		return "", &AgentCardError{Code: "malformed", Message: "a number is not finite"}
	}
	if f == 0 {
		return "0", nil
	}
	sign := ""
	if f < 0 {
		sign, f = "-", -f
	}
	s := strconv.FormatFloat(f, 'e', -1, 64)
	i := strings.IndexByte(s, 'e')
	digits := strings.Replace(s[:i], ".", "", 1)
	e, _ := strconv.Atoi(s[i+1:])
	k, n := len(digits), e+1
	var out string
	switch {
	case k <= n && n <= 21:
		out = digits + strings.Repeat("0", n-k)
	case 0 < n && n <= 21:
		out = digits[:n] + "." + digits[n:]
	case -6 < n && n <= 0:
		out = "0." + strings.Repeat("0", -n) + digits
	default:
		x := n - 1
		out = digits[:1]
		if k > 1 {
			out += "." + digits[1:]
		}
		if x >= 0 {
			out += "e+" + strconv.Itoa(x)
		} else {
			out += "e-" + strconv.Itoa(-x)
		}
	}
	return sign + out, nil
}

func jcsString(b *strings.Builder, s string) {
	b.WriteByte('"')
	for _, r := range s {
		switch r {
		case '"':
			b.WriteString(`\"`)
		case '\\':
			b.WriteString(`\\`)
		case '\b':
			b.WriteString(`\b`)
		case '\f':
			b.WriteString(`\f`)
		case '\n':
			b.WriteString(`\n`)
		case '\r':
			b.WriteString(`\r`)
		case '\t':
			b.WriteString(`\t`)
		default:
			if r < 0x20 {
				fmt.Fprintf(b, `\u%04x`, r)
			} else {
				b.WriteRune(r)
			}
		}
	}
	b.WriteByte('"')
}

func utf16Less(a, b string) bool {
	x, y := utf16.Encode([]rune(a)), utf16.Encode([]rune(b))
	for i := 0; i < len(x) && i < len(y); i++ {
		if x[i] != y[i] {
			return x[i] < y[i]
		}
	}
	return len(x) < len(y)
}

func jcsWrite(b *strings.Builder, v interface{}) error {
	switch t := v.(type) {
	case nil:
		b.WriteString("null")
	case bool:
		if t {
			b.WriteString("true")
		} else {
			b.WriteString("false")
		}
	case string:
		jcsString(b, t)
	case json.Number:
		f, err := t.Float64()
		if err != nil {
			return &AgentCardError{Code: "malformed", Message: "a number is out of range"}
		}
		s, err := esNumber(f)
		if err != nil {
			return err
		}
		b.WriteString(s)
	case float64:
		s, err := esNumber(t)
		if err != nil {
			return err
		}
		b.WriteString(s)
	case int:
		b.WriteString(strconv.Itoa(t))
	case []interface{}:
		b.WriteByte('[')
		for i, x := range t {
			if i > 0 {
				b.WriteByte(',')
			}
			if err := jcsWrite(b, x); err != nil {
				return err
			}
		}
		b.WriteByte(']')
	case map[string]interface{}:
		keys := make([]string, 0, len(t))
		for k := range t {
			keys = append(keys, k)
		}
		sort.Slice(keys, func(i, j int) bool { return utf16Less(keys[i], keys[j]) })
		b.WriteByte('{')
		for i, k := range keys {
			if i > 0 {
				b.WriteByte(',')
			}
			jcsString(b, k)
			b.WriteByte(':')
			if err := jcsWrite(b, t[k]); err != nil {
				return err
			}
		}
		b.WriteByte('}')
	default:
		return &AgentCardError{Code: "malformed", Message: fmt.Sprintf("cannot canonicalize %T", v)}
	}
	return nil
}

// CanonicalJSON writes a JSON value in RFC 8785 form (sorted keys in UTF-16
// order, no whitespace, ECMAScript numbers). Decode with UseNumber to keep numbers exact.
func CanonicalJSON(v interface{}) (string, error) {
	var b strings.Builder
	if err := jcsWrite(&b, v); err != nil {
		return "", err
	}
	return b.String(), nil
}

func decodeCard(card []byte) (map[string]interface{}, error) {
	d := json.NewDecoder(bytes.NewReader(card))
	d.UseNumber()
	var c map[string]interface{}
	if err := d.Decode(&c); err != nil || c == nil {
		return nil, &AgentCardError{Code: "malformed", Message: "the card is not a JSON object"}
	}
	return c, nil
}

func cardPayload(c map[string]interface{}) (string, error) {
	rest := make(map[string]interface{}, len(c))
	for k, v := range c {
		if k != "signatures" {
			rest[k] = v
		}
	}
	s, err := CanonicalJSON(rest)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString([]byte(s)), nil
}

func cardHost(raw string) string {
	if raw == "" || !xaaSafeURL(raw) {
		return ""
	}
	u, _ := url.Parse(raw)
	return u.Host
}

// VerifyAgentCard checks the card's signatures: the one that verified, or *AgentCardError.
func VerifyAgentCard(ctx context.Context, card []byte, opts VerifyAgentCardOptions) (*AgentCardVerification, error) {
	c, err := decodeCard(card)
	if err != nil {
		return nil, err
	}
	sigs, _ := c["signatures"].([]interface{})
	if len(sigs) == 0 {
		return nil, &AgentCardError{Code: "unsigned", Message: "the card has no signatures"}
	}
	payload, err := cardPayload(c)
	if err != nil {
		return nil, err
	}
	client := opts.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: 5 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	}
	host := cardHost(opts.CardURL)
	last := &AgentCardError{Code: "invalid_signature", Message: "no signature verifies"}
	for _, raw := range sigs {
		s, _ := raw.(map[string]interface{})
		prot, _ := s["protected"].(string)
		sigText, _ := s["signature"].(string)
		if prot == "" || sigText == "" {
			continue
		}
		head, err := mcpJSONPart(prot)
		if err != nil {
			continue
		}
		alg, _ := head["alg"].(string)
		kid, _ := head["kid"].(string)
		if (alg != "RS256" && alg != "ES256" && alg != "EdDSA") || kid == "" || head["crit"] != nil {
			continue
		}
		if typ, ok := head["typ"]; ok && typ != "JOSE" {
			continue
		}
		var jwk map[string]interface{}
		for _, k := range opts.Keys {
			if k["kid"] == kid {
				jwk = k
				break
			}
		}
		source := "keys"
		if jwk == nil {
			if jku, ok := head["jku"].(string); ok {
				jh := cardHost(jku)
				trusted := jh != "" && (jh == host || containsString(opts.TrustedJKUHosts, jh))
				if !trusted {
					last = &AgentCardError{Code: "untrusted_key", Message: "jku " + jku + " is not on the card's host"}
					continue
				}
				set, err := xaaGetJSON(ctx, client, jku)
				if err != nil {
					last = &AgentCardError{Code: "keys_unavailable", Message: "the keys at " + jku + " could not be read: " + err.Error()}
					continue
				}
				list, _ := set["keys"].([]interface{})
				for _, x := range list {
					if k, ok := x.(map[string]interface{}); ok && k["kid"] == kid {
						jwk = k
						break
					}
				}
				source = "jku"
			}
		}
		if jwk == nil {
			if last.Code == "invalid_signature" {
				last = &AgentCardError{Code: "untrusted_key", Message: "no trusted key " + kid}
			}
			continue
		}
		key, err := mcpPublicKey(jwk)
		if err != nil {
			continue
		}
		sig, err := base64.RawURLEncoding.DecodeString(sigText)
		if err == nil && mcpVerifySignature(prot+"."+payload, sig, alg, key) {
			return &AgentCardVerification{KID: kid, Alg: alg, KeySource: source}, nil
		}
		last = &AgentCardError{Code: "invalid_signature", Message: "the signature does not match the card"}
	}
	return nil, last
}

func containsString(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

// SignAgentCard signs a card you publish (EC P-256, Ed25519 or RSA key): the
// card with one more entry in `signatures`, as JSON. key may be any
// crypto.Signer, e.g. one backed by a KMS or an HSM.
func SignAgentCard(card []byte, key crypto.Signer, kid, jku string) ([]byte, error) {
	c, err := decodeCard(card)
	if err != nil {
		return nil, err
	}
	var alg string
	switch pub := key.Public().(type) {
	case *ecdsa.PublicKey:
		if pub.Curve != elliptic.P256() {
			return nil, &AgentCardError{Code: "malformed", Message: "an EC key must be on P-256 (ES256)"}
		}
		alg = "ES256"
	case ed25519.PublicKey:
		alg = "EdDSA"
	case *rsa.PublicKey:
		alg = "RS256"
	default:
		return nil, &AgentCardError{Code: "malformed", Message: "the key must be EC P-256, Ed25519 or RSA"}
	}
	header := map[string]interface{}{"alg": alg, "typ": "JOSE", "kid": kid}
	if jku != "" {
		header["jku"] = jku
	}
	hb, _ := json.Marshal(header)
	prot := base64.RawURLEncoding.EncodeToString(hb)
	payload, err := cardPayload(c)
	if err != nil {
		return nil, err
	}
	input := []byte(prot + "." + payload)
	var sig []byte
	switch alg {
	case "EdDSA":
		sig, err = key.Sign(rand.Reader, input, crypto.Hash(0))
	case "ES256":
		// A crypto.Signer answers ASN.1 DER; JWS wants r || s.
		sum := sha256.Sum256(input)
		var der []byte
		if der, err = key.Sign(rand.Reader, sum[:], crypto.SHA256); err == nil {
			sig, err = es256RawSignature(der)
		}
	default:
		sum := sha256.Sum256(input)
		sig, err = key.Sign(rand.Reader, sum[:], crypto.SHA256)
	}
	if err != nil {
		return nil, err
	}
	prior, _ := c["signatures"].([]interface{})
	c["signatures"] = append(prior, map[string]interface{}{"protected": prot, "signature": base64.RawURLEncoding.EncodeToString(sig)})
	var out bytes.Buffer
	enc := json.NewEncoder(&out)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(c); err != nil {
		return nil, err
	}
	return bytes.TrimRight(out.Bytes(), "\n"), nil
}

// es256RawSignature turns an ASN.1 DER ECDSA P-256 signature into the
// 64-byte r || s of JWS.
func es256RawSignature(der []byte) ([]byte, error) {
	var rs struct{ R, S *big.Int }
	rest, err := asn1.Unmarshal(der, &rs)
	if err != nil || len(rest) != 0 || rs.R == nil || rs.S == nil || rs.R.Sign() <= 0 || rs.S.Sign() <= 0 || rs.R.BitLen() > 256 || rs.S.BitLen() > 256 {
		return nil, &AgentCardError{Code: "malformed", Message: "the key did not answer an ECDSA P-256 signature"}
	}
	return append(leftPad(rs.R, 32), leftPad(rs.S, 32)...), nil
}

func leftPad(n *big.Int, size int) []byte {
	b := n.Bytes()
	if len(b) >= size {
		return b
	}
	return append(make([]byte, size-len(b)), b...)
}
