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

// OfflineOutageScope is what outage codes are for: one organization, or your
// own outage server(s). Each scope has its own codes, so digests fetched for
// one scope are worthless for any other, and VerifyTotp never accepts an
// outage code.
type OfflineOutageScope struct {
	// ID: 1-64 characters of a-z, 0-9, ".", "_", "-" (compared in lower case). Keep it stable.
	ID string `json:"id"`
	// Name: 1-80 characters, shown on the user's phone under the normal
	// time-based code: "<name>: code for when Touchque can't be reached".
	Name string `json:"name"`
}

// OfflineTotpVerifiersOptions holds the POST /offline/totp/verifiers fields.
type OfflineTotpVerifiersOptions struct {
	// ExternalUsernames: up to 1,000 users; users x steps at most 24,000 a call.
	ExternalUsernames []string
	// Scope is required: the organization or server these codes are for. The
	// user's phone shows this scope's code once a call has named it for them.
	Scope OfflineOutageScope
	// FromStep: the first 30-second step (0: the current one).
	FromStep int64
	// Steps: how many, 1-480 (0: 480, four hours).
	Steps int
}

// OfflineTotpVerifierUser is one user's digests.
type OfflineTotpVerifierUser struct {
	ExternalUsername string `json:"externalUsername"`
	// FromStep: this user's first step.
	FromStep int64 `json:"fromStep"`
	// Salt: base64, 16 bytes.
	Salt string `json:"salt"`
	// Digests: base64, KDF.Length bytes per digest, DigestsPerStep digests per
	// step from FromStep.
	Digests string `json:"digests"`
}

// OfflineTotpVerifiers is returned by TotpVerifiers.
type OfflineTotpVerifiers struct {
	StepSeconds  int64 `json:"stepSeconds"`
	FromStep     int64 `json:"fromStep"`
	Steps        int   `json:"steps"`
	NotAfterStep int64 `json:"notAfterStep"`
	// Scope is the scope as Touchque stored it (id in lower case, name cleaned).
	Scope *OfflineOutageScope `json:"scope,omitempty"`
	// DigestsPerStep: 1, the scope's outage code (answers without it, 0 here, had 2).
	DigestsPerStep int `json:"digestsPerStep"`
	KDF            struct {
		Name       string `json:"name"`
		Iterations int    `json:"iterations"`
		Length     int    `json:"length"`
	} `json:"kdf"`
	// Users: only those who can use time-based codes now and whose phone shows this scope.
	Users []OfflineTotpVerifierUser `json:"users"`
}

// TotpVerifiers is for checking typed codes while your server cannot reach
// Touchque (an outage): salted, slow digests of each user's next OUTAGE codes
// for one scope, never a key. Outage codes are not the normal time-based code:
// each scope (an organization, or your own outage server) has its own, the
// user's phone shows them under the normal code ("<name>: code for when
// Touchque can't be reached") once a call has named the scope for the user,
// and VerifyTotp never accepts them. Check a typed code with
// MatchTotpVerifier. Requires the workspace policies offlineTotpEnabled and
// outageVerifiersEnabled. Fetch again every few minutes from the step you
// have: removed and frozen users fall out. Quotas are per scope (429
// scope_quota_exceeded) and per workspace.
func (o *OfflineResource) TotpVerifiers(opts OfflineTotpVerifiersOptions) (*OfflineTotpVerifiers, error) {
	body := map[string]interface{}{"externalUsernames": opts.ExternalUsernames, "scope": opts.Scope}
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
// calling Touchque. It returns the step the code belongs to (the current one
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
	return matchDigests(digests, salt, user.FromStep, v.NotAfterStep, v.KDF.Iterations, v.KDF.Length, v.DigestsPerStep, given, at.Unix()/v.StepSeconds)
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

// matchDigests is MatchTotpVerifier on decoded values (given: a normalized
// code; now: the current step; perStep: digests per step, 0 means 2 as in
// answers that predate DigestsPerStep).
func matchDigests(digests, salt []byte, fromStep, notAfterStep int64, iterations, length, perStep int, given string, now int64) (int64, bool) {
	if perStep <= 0 {
		perStep = 2
	}
	for _, step := range []int64{now, now - 1, now + 1} {
		if step < fromStep || step > notAfterStep {
			continue
		}
		at := int(step-fromStep) * perStep * length
		if at+perStep*length > len(digests) {
			continue
		}
		s := append(append([]byte{}, salt...), []byte(":"+strconv.FormatInt(step, 10))...)
		got, err := pbkdf2.Key(sha256.New, given, s, iterations, length)
		if err != nil {
			return 0, false
		}
		for k := 0; k < perStep; k++ {
			if subtle.ConstantTimeCompare(digests[at+k*length:at+(k+1)*length], got) == 1 {
				return step, true
			}
		}
	}
	return 0, false
}
