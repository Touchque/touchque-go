package touchque

// What a partner's server checks before executing what an AI agent asked
// for: the approval token's claims match the transaction (person, action
// type, authorization details), and, offline, its ES256 signature against
// TouchQue's keys (GET /agents/jwks.json). Matching rules
// (fixtures/agent-vectors.json): every expected field must be equal, extra
// fields are ignored; amounts compare as decimals ("500" = "500.00"), IBANs
// without spaces and in any case, currencies in any case; a map matches a
// token with exactly one entry, a slice matches entry by entry with the same
// length.

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"reflect"
	"regexp"
	"strings"
	"time"
)

var decimalPattern = regexp.MustCompile(`^\d+(\.\d+)?$`)

func normalDecimal(v interface{}) (string, bool) {
	text := strings.TrimSpace(toString(v))
	if !decimalPattern.MatchString(text) {
		return "", false
	}
	parts := strings.SplitN(text, ".", 2)
	whole := strings.TrimLeft(parts[0], "0")
	if whole == "" {
		whole = "0"
	}
	frac := ""
	if len(parts) == 2 {
		frac = strings.TrimRight(parts[1], "0")
	}
	if frac == "" {
		return whole, true
	}
	return whole + "." + frac, true
}

func toString(v interface{}) string {
	switch t := v.(type) {
	case string:
		return t
	case float64:
		b, _ := json.Marshal(t)
		return string(b)
	default:
		b, _ := json.Marshal(t)
		return string(b)
	}
}

func sameValue(key string, actual, expected interface{}) bool {
	switch expected.(type) {
	case map[string]interface{}, []interface{}:
		return partialMatch(actual, expected)
	}
	switch key {
	case "amount":
		a, ok1 := normalDecimal(actual)
		e, ok2 := normalDecimal(expected)
		return ok1 && ok2 && a == e
	case "iban", "currency":
		s, ok := actual.(string)
		norm := func(x string) string { return strings.ToUpper(strings.Join(strings.Fields(x), "")) }
		return ok && norm(s) == norm(toString(expected))
	}
	return reflect.DeepEqual(actual, expected)
}

func partialMatch(actual, expected interface{}) bool {
	if list, ok := expected.([]interface{}); ok {
		got, ok := actual.([]interface{})
		if !ok || len(got) != len(list) {
			return false
		}
		for i, e := range list {
			if _, isMap := e.(map[string]interface{}); isMap {
				if !partialMatch(got[i], e) {
					return false
				}
			} else if !reflect.DeepEqual(got[i], e) {
				return false
			}
		}
		return true
	}
	want, ok := expected.(map[string]interface{})
	if !ok {
		return false
	}
	got, ok := actual.(map[string]interface{})
	if !ok {
		return false
	}
	for k, v := range want {
		a, present := got[k]
		if !present || !sameValue(k, a, v) {
			return false
		}
	}
	return true
}

// normalizeJSON turns any value (structs, typed maps) into plain JSON values.
func normalizeJSON(v interface{}) interface{} {
	b, err := json.Marshal(v)
	if err != nil {
		return nil
	}
	var out interface{}
	_ = json.Unmarshal(b, &out)
	return out
}

// MatchesAuthorizationDetails says whether details (a token's
// authorization_details) say what expected says: a map (one entry) or a slice
// of maps (every entry, same length).
func MatchesAuthorizationDetails(details interface{}, expected interface{}) bool {
	got, ok := normalizeJSON(details).([]interface{})
	if !ok {
		return false
	}
	switch want := normalizeJSON(expected).(type) {
	case []interface{}:
		if len(got) != len(want) {
			return false
		}
		for i := range want {
			if !partialMatch(got[i], want[i]) {
				return false
			}
		}
		return true
	case map[string]interface{}:
		return len(got) == 1 && partialMatch(got[0], want)
	}
	return false
}

// ApprovalExpectation is what the executor is about to do; empty fields are not checked.
type ApprovalExpectation struct {
	User string
	Type string
	// AuthorizationDetails: one entry (a map, the token must hold exactly one) or every entry in order (a slice).
	AuthorizationDetails interface{}
}

// AssertApprovalMatches returns an *ApprovalMismatchError unless the claims say what expect says.
func AssertApprovalMatches(claims map[string]interface{}, expect ApprovalExpectation) error {
	if expect.User != "" && claims["sub"] != expect.User {
		return &ApprovalMismatchError{Message: "the approval is for another person"}
	}
	if expect.Type != "" && claims["type"] != expect.Type {
		return &ApprovalMismatchError{Message: "the approval is for another action type (" + toString(claims["type"]) + ")"}
	}
	if expect.AuthorizationDetails != nil && !MatchesAuthorizationDetails(claims["authorization_details"], expect.AuthorizationDetails) {
		return &ApprovalMismatchError{Message: "the approved details differ from what you are about to execute"}
	}
	return nil
}

// DecodeApprovalToken returns the header and claims WITHOUT checking the signature.
func DecodeApprovalToken(token string) (map[string]interface{}, map[string]interface{}, error) {
	parts := strings.Split(token, ".")
	bad := &ApprovalMismatchError{Message: "not an approval token"}
	if len(parts) != 3 {
		return nil, nil, bad
	}
	var header, claims map[string]interface{}
	h, err1 := base64.RawURLEncoding.DecodeString(parts[0])
	c, err2 := base64.RawURLEncoding.DecodeString(parts[1])
	if err1 != nil || err2 != nil || json.Unmarshal(h, &header) != nil || json.Unmarshal(c, &claims) != nil {
		return nil, nil, bad
	}
	return header, claims, nil
}

// JWKS is a JSON Web Key Set, as GET /agents/jwks.json answers.
type JWKS struct {
	Keys []map[string]interface{} `json:"keys"`
}

// VerifyApprovalTokenWith verifies an approval token offline: typ
// touchque-approval+jwt, ES256 by a key of jwks, not expired (30 s leeway),
// aud equal to audience, then expect. now: zero means the current time.
// audience is required: GET /agents/jwks.json is one key set for every
// Touchque workspace, so without it a token Touchque signed for another
// workspace would pass. Pass your own (Agents.ApprovalAudience,
// touchque:workspace:<id>), or use Agents.VerifyApprovalToken, which fills it
// in. It does not make the token single-use: Agents.RedeemApproval does.
func VerifyApprovalTokenWith(token string, jwks JWKS, audience string, expect ApprovalExpectation, now time.Time) (map[string]interface{}, error) {
	if audience == "" {
		return nil, &ApprovalMismatchError{Message: "audience is required: your workspace's touchque:workspace:<id> (Agents.ApprovalAudience)"}
	}
	header, claims, err := DecodeApprovalToken(token)
	if err != nil {
		return nil, err
	}
	if header["typ"] != "touchque-approval+jwt" || header["alg"] != "ES256" {
		return nil, &ApprovalMismatchError{Message: "not an approval token (typ/alg)"}
	}
	var jwk map[string]interface{}
	for _, k := range jwks.Keys {
		if k["kid"] == header["kid"] && k["kty"] == "EC" && k["crv"] == "P-256" {
			jwk = k
		}
	}
	if jwk == nil {
		return nil, &ApprovalMismatchError{Message: "signed by an unknown key"}
	}
	xs, _ := jwk["x"].(string)
	ys, _ := jwk["y"].(string)
	x, err1 := base64.RawURLEncoding.DecodeString(xs)
	y, err2 := base64.RawURLEncoding.DecodeString(ys)
	parts := strings.Split(token, ".")
	sig, err3 := base64.RawURLEncoding.DecodeString(parts[2])
	if err1 != nil || err2 != nil || err3 != nil || len(sig) != 64 {
		return nil, &ApprovalMismatchError{Message: "the signature does not verify"}
	}
	pub := &ecdsa.PublicKey{Curve: elliptic.P256(), X: new(big.Int).SetBytes(x), Y: new(big.Int).SetBytes(y)}
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if !ecdsa.Verify(pub, digest[:], new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:])) {
		return nil, &ApprovalMismatchError{Message: "the signature does not verify"}
	}
	if now.IsZero() {
		now = time.Now()
	}
	exp, ok := claims["exp"].(float64)
	if !ok || int64(exp)+30 < now.Unix() {
		return nil, &ApprovalMismatchError{Message: "the approval token expired"}
	}
	if aud, _ := claims["aud"].(string); aud == "" {
		return nil, &ApprovalMismatchError{Message: "the approval token names no workspace"}
	} else if aud != audience {
		return nil, &ApprovalMismatchError{Message: "the approval token is for another workspace"}
	}
	if err := AssertApprovalMatches(claims, expect); err != nil {
		return nil, err
	}
	return claims, nil
}
