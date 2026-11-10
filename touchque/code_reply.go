package touchque

// A code the person types back on the phone (LoginRequestOptions.Reply): a
// sign-in code another service sent them (a text message, WhatsApp, e-mail).
// Each request gets a one-time P-256 key pair; its public key goes with the
// request, the phone encrypts what was typed to it, and only you can open it:
// TouchQue stores and hands back nothing but the ciphertext
// (LoginStatusResponse.Reply.CT).
//
// ECDH P-256, HKDF-SHA256 (salt: the request id, info
// "touchque-code-reply-v1"), AES-256-GCM (additional data
// "touchque-code-reply:<request id>"), as
// "v1.<the phone's one-time key, x9.63>.<nonce|ciphertext|tag>", base64url.

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"regexp"
	"strings"
)

// LoginReplyRequest asks the person to type something back on the phone:
// today Kind "code", a sign-in code another service sent them. Key is a
// one-time P-256 public key (NewCodeReplyKey().PublicKey). Channel (sms,
// whatsapp, email, app, backup, other) and Target (the masked number or
// address, at most 40 characters) are shown on the phone.
type LoginReplyRequest struct {
	Kind    string `json:"kind"`
	Key     string `json:"key"`
	Channel string `json:"channel,omitempty"`
	Target  string `json:"target,omitempty"`
}

// LoginReply is what a request made with Reply holds once the person typed it
// back: the ciphertext only (open it with OpenCodeReply) and when.
type LoginReply struct {
	CT string `json:"ct"`
	At string `json:"at,omitempty"`
}

// CodeReplyKey is a one-time key pair for one request: send PublicKey (the
// uncompressed P-256 point, base64url) as LoginReplyRequest.Key, keep
// PrivateKey (PKCS#8 DER, base64url) server-side for this one request.
type CodeReplyKey struct {
	PublicKey  string
	PrivateKey string
}

var (
	codeReplyCT   = regexp.MustCompile(`^v1\.([A-Za-z0-9_-]+)\.([A-Za-z0-9_-]+)$`)
	codeReplyCode = regexp.MustCompile(`^[A-Za-z0-9 -]{4,20}$`)
)

// NewCodeReplyKey makes a one-time key pair for LoginRequestOptions.Reply.
func NewCodeReplyKey() (CodeReplyKey, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return CodeReplyKey{}, err
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return CodeReplyKey{}, err
	}
	pub, err := key.PublicKey.ECDH()
	if err != nil {
		return CodeReplyKey{}, err
	}
	return CodeReplyKey{PublicKey: base64.RawURLEncoding.EncodeToString(pub.Bytes()), PrivateKey: base64.RawURLEncoding.EncodeToString(der)}, nil
}

// OpenCodeReply returns the code the person typed, or false when ct does not
// open with this key for this request (or is not a code).
func OpenCodeReply(privateKey, requestID, ct string) (string, bool) {
	m := codeReplyCT.FindStringSubmatch(ct)
	if m == nil {
		return "", false
	}
	epk, err1 := base64.RawURLEncoding.DecodeString(m[1])
	box, err2 := base64.RawURLEncoding.DecodeString(m[2])
	der, err3 := base64.RawURLEncoding.DecodeString(privateKey)
	if err1 != nil || err2 != nil || err3 != nil || len(epk) != 65 || epk[0] != 4 || len(box) < 12+16+1 {
		return "", false
	}
	parsed, err := x509.ParsePKCS8PrivateKey(der)
	if err != nil {
		return "", false
	}
	ecKey, ok := parsed.(*ecdsa.PrivateKey)
	if !ok {
		return "", false
	}
	priv, err := ecKey.ECDH()
	if err != nil {
		return "", false
	}
	peer, err := ecdh.P256().NewPublicKey(epk)
	if err != nil {
		return "", false
	}
	shared, err := priv.ECDH(peer)
	if err != nil {
		return "", false
	}
	key, err := hkdf.Key(sha256.New, shared, []byte(requestID), "touchque-code-reply-v1", 32)
	if err != nil {
		return "", false
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", false
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", false
	}
	plain, err := gcm.Open(nil, box[:12], box[12:], []byte("touchque-code-reply:"+requestID))
	if err != nil {
		return "", false
	}
	code := strings.TrimSpace(string(plain))
	if !codeReplyCode.MatchString(code) {
		return "", false
	}
	return code, true
}
