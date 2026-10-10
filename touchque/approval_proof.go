package touchque

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"strings"
)

// ApprovalProof is the device-signed proof of an approval ("what you see is
// what you sign"). When the user's phone holds a hardware key (Secure Enclave
// / Android Keystore), every approval is signed by it over the request id, the
// action type, the number-match code and a digest of the transaction details
// the user was shown. It arrives in the SUCCESS webhook ("approvalProof") and
// in the login status response. Verifying it does not require trusting
// TouchQue: it proves the enrolled phone signed exactly these details.
type ApprovalProof struct {
	Version   string `json:"version"`
	Algorithm string `json:"algorithm"`
	// Message is the exact text the device signed.
	Message string `json:"message"`
	// Signature is the base64 DER ECDSA signature.
	Signature string `json:"signature"`
	// PublicKey is the base64 X9.63 (uncompressed) P-256 key of the device.
	PublicKey string `json:"publicKey"`
}

// VerifyApprovalProofOptions describes the transaction you expect the proof
// to cover.
type VerifyApprovalProofOptions struct {
	// RequestID returned by the login request.
	RequestID string
	// Type is the action type you sent (e.g. "WITHDRAW").
	Type string
	// Details you sent, exactly as you sent them (nil when none).
	Details []LoginDetail
	// ChallengeCode is the number-match code, when number matching was used.
	ChallengeCode string
	// ExpectedPublicKey pins the device: the base64 public key you stored for
	// this user (e.g. PublicKey of their first verified approval). A proof
	// from any other key is rejected. Required unless AllowUnpinnedKey.
	ExpectedPublicKey string
	// AllowUnpinnedKey accepts whatever key the proof carries. Without a pin
	// the proof only shows that *some* key signed these details. Only for
	// trust-on-first-use: store PublicKey after this first check, pin it after.
	AllowUnpinnedKey bool
}

// DetailsDigest is the SHA-256 hex of the details as displayed on the phone
// ("" when there are none) — the last line of the signed message.
func DetailsDigest(details []LoginDetail) string { return detailsDigest(details) }

// VerifyApprovalProof reports whether proof was signed by the device key over
// exactly the request, action type, challenge code and details in opts.
// proof may be an ApprovalProof, *ApprovalProof, the decoded JSON value from a
// webhook or status response (map[string]interface{}), json.RawMessage or
// []byte. Fails closed (no pin and no AllowUnpinnedKey -> false) and returns
// false for any malformed input.
func VerifyApprovalProof(proof interface{}, opts VerifyApprovalProofOptions) bool {
	p, ok := toApprovalProof(proof)
	if !ok || p.Version != "v2" || p.Algorithm != "ECDSA-P256-SHA256" {
		return false
	}
	if opts.ExpectedPublicKey != "" {
		if subtle.ConstantTimeCompare([]byte(p.PublicKey), []byte(opts.ExpectedPublicKey)) != 1 {
			return false
		}
	} else if !opts.AllowUnpinnedKey {
		return false
	}

	expected := strings.Join([]string{
		"touchque-approve:v2", opts.RequestID, opts.Type, opts.ChallengeCode, detailsDigest(opts.Details),
	}, "\n")
	if subtle.ConstantTimeCompare([]byte(p.Message), []byte(expected)) != 1 {
		return false
	}

	raw, err := base64.StdEncoding.DecodeString(p.PublicKey)
	if err != nil || len(raw) != 65 || raw[0] != 0x04 {
		return false
	}
	key, err := ecdsa.ParseUncompressedPublicKey(elliptic.P256(), raw)
	if err != nil {
		return false // not a point on P-256
	}
	sig, err := base64.StdEncoding.DecodeString(p.Signature)
	if err != nil || len(sig) == 0 {
		return false
	}
	digest := sha256.Sum256([]byte(p.Message))
	return ecdsa.VerifyASN1(key, digest[:], sig)
}

func toApprovalProof(v interface{}) (ApprovalProof, bool) {
	switch t := v.(type) {
	case nil:
		return ApprovalProof{}, false
	case ApprovalProof:
		return t, true
	case *ApprovalProof:
		if t == nil {
			return ApprovalProof{}, false
		}
		return *t, true
	case json.RawMessage:
		return decodeApprovalProof(t)
	case []byte:
		return decodeApprovalProof(t)
	default:
		b, err := json.Marshal(t)
		if err != nil {
			return ApprovalProof{}, false
		}
		return decodeApprovalProof(b)
	}
}

func decodeApprovalProof(b []byte) (ApprovalProof, bool) {
	var p ApprovalProof
	if err := json.Unmarshal(b, &p); err != nil {
		return ApprovalProof{}, false
	}
	return p, true
}
