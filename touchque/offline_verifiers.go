package touchque

import (
	"crypto/pbkdf2"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"strconv"
	"strings"
	"time"
)

// OfflineTotpVerifiersOptions holds the POST /offline/totp/verifiers fields.
type OfflineTotpVerifiersOptions struct {
	// ExternalUsernames: up to 1,000 users; users x steps at most 24,000 a call.
	ExternalUsernames []string
	// FromStep: the first 30-second step (0: the current one).
	FromStep int64
	// Steps: how many, 1-480 (0: 480, four hours).
	Steps int
}

// OfflineTotpVerifierUser is one user's digests.
type OfflineTotpVerifierUser struct {
	ExternalUsername string `json:"externalUsername"`
	// FromStep: this user's first step (later than asked when earlier steps were used).
	FromStep int64 `json:"fromStep"`
	// Salt: base64, 16 bytes.
	Salt string `json:"salt"`
	// Digests: base64, KDF.Length bytes per digest, two per step from FromStep
	// (the anchored and the unanchored code).
	Digests string `json:"digests"`
}

// OfflineTotpVerifiers is returned by TotpVerifiers.
type OfflineTotpVerifiers struct {
	StepSeconds  int64 `json:"stepSeconds"`
	FromStep     int64 `json:"fromStep"`
	Steps        int   `json:"steps"`
	NotAfterStep int64 `json:"notAfterStep"`
	KDF          struct {
		Name       string `json:"name"`
		Iterations int    `json:"iterations"`
		Length     int    `json:"length"`
	} `json:"kdf"`
	// Users: only those who can use time-based codes now.
	Users []OfflineTotpVerifierUser `json:"users"`
}

// TotpVerifiers is for checking typed time-based codes while your server
// cannot reach TouchQue (an outage): salted, slow digests of each user's next
// codes, never a key. Check a typed code with MatchTotpVerifier. Requires the
// workspace policies offlineTotpEnabled and outageVerifiersEnabled. Fetch
// again every few minutes: removed and frozen users fall out.
func (o *OfflineResource) TotpVerifiers(opts OfflineTotpVerifiersOptions) (*OfflineTotpVerifiers, error) {
	body := map[string]interface{}{"externalUsernames": opts.ExternalUsernames}
	if opts.FromStep > 0 {
		body["fromStep"] = opts.FromStep
	}
	if opts.Steps > 0 {
		body["steps"] = opts.Steps
	}
	res, err := o.http.post("/offline/totp/verifiers", body)
	if err != nil {
		return nil, err
	}
	out := &OfflineTotpVerifiers{}
	if err := decodeInto(res, out); err != nil {
		return nil, err
	}
	return out, nil
}

const offlineCodeAlphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"

// MatchTotpVerifier checks a typed code against one user's digests without
// calling TouchQue. It returns the step the code belongs to (the current one
// or one either side) and true, or false. Accept each step once: remember the
// step you accepted for the user and refuse codes for it or an older one.
func MatchTotpVerifier(v *OfflineTotpVerifiers, user *OfflineTotpVerifierUser, code string, at time.Time) (int64, bool) {
	given, ok := normalizeOfflineCode(code)
	if !ok || v == nil || user == nil || v.StepSeconds <= 0 {
		return 0, false
	}
	salt, err := base64.StdEncoding.DecodeString(user.Salt)
	if err != nil {
		return 0, false
	}
	digests, err := base64.StdEncoding.DecodeString(user.Digests)
	if err != nil || v.KDF.Length <= 0 {
		return 0, false
	}
	return matchDigests(digests, salt, user.FromStep, v.NotAfterStep, v.KDF.Iterations, v.KDF.Length, given, at.Unix()/v.StepSeconds)
}

// normalizeOfflineCode upper-cases a typed code and drops spaces and dashes;
// false unless it is 7 characters of the codes' alphabet.
func normalizeOfflineCode(code string) (string, bool) {
	given := strings.NewReplacer(" ", "", "-", "", "\t", "").Replace(strings.ToUpper(code))
	if len(given) != 7 {
		return "", false
	}
	for _, c := range given {
		if !strings.ContainsRune(offlineCodeAlphabet, c) {
			return "", false
		}
	}
	return given, true
}

// matchDigests is MatchTotpVerifier on decoded values (given: a normalized code; now: the current step).
func matchDigests(digests, salt []byte, fromStep, notAfterStep int64, iterations, length int, given string, now int64) (int64, bool) {
	for _, step := range []int64{now, now - 1, now + 1} {
		if step < fromStep || step > notAfterStep {
			continue
		}
		at := int(step-fromStep) * 2 * length
		if at+2*length > len(digests) {
			continue
		}
		s := append(append([]byte{}, salt...), []byte(":"+strconv.FormatInt(step, 10))...)
		got, err := pbkdf2.Key(sha256.New, given, s, iterations, length)
		if err != nil {
			return 0, false
		}
		if subtle.ConstantTimeCompare(digests[at:at+length], got) == 1 || subtle.ConstantTimeCompare(digests[at+length:at+2*length], got) == 1 {
			return step, true
		}
	}
	return 0, false
}
