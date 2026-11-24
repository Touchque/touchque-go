package touchque

import (
	"crypto/pbkdf2"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"math"
	"strconv"
	"strings"
	"time"
)

// Offline sign-in packs: a device with no network (a laptop for days, a
// kiosk, a field tablet) keeps a person's next offline sign-ins. Your server
// asks for a pack with IssueDevicePack; the device checks a typed code with
// VerifyDeviceCode, reports the slots it used with ReportDevicePackUse once it
// is back online, and a lost device is stopped with RevokeDeviceScope.

// OfflineDeviceScope is the device an offline sign-in pack is for.
type OfflineDeviceScope struct {
	// ID: 1-64 characters of a-z, 0-9, ".", "_", "-", starting with a letter
	// or a digit (compared in lower case). One id per device for as long as it
	// is installed; a reinstalled device gets a new one.
	ID string `json:"id"`
	// Name: 1-80 characters, the device's name shown on the person's phone.
	Name string `json:"name"`
	// Epoch is set in answers only: random per person and device.
	Epoch string `json:"epoch,omitempty"`
}

// OfflineDevicePackOptions holds the POST /offline/device-packs fields.
type OfflineDevicePackOptions struct {
	ExternalUsername string
	// Scope is the device (ID and Name; Epoch is not sent).
	Scope OfflineDeviceScope
	// Account is the account the person signs in to on that device
	// (ACME\jane), 1-255 characters, shown on the phone.
	Account string
	// Count: how many new slots (offline sign-ins), 1-20 (0: the default, 10).
	Count int
	// ValidDays: how long the slots are valid for, from now, 1-30 days (0: the
	// default, 14).
	ValidDays int
}

// OfflineDeviceKDF is how the slot digests were made: PBKDF2-SHA256 with
// Iterations iterations and Length bytes.
type OfflineDeviceKDF struct {
	Name       string `json:"name"`
	Iterations int    `json:"iterations"`
	Length     int    `json:"length"`
}

// OfflineDeviceSlot is one offline sign-in: the slow digest of its
// 10-character code and the QR only the person's phone opens.
type OfflineDeviceSlot struct {
	// Index is the slot number; Touchque never issues an index twice.
	Index int `json:"index"`
	// Salt: base64.
	Salt string `json:"salt"`
	// Digest: base64, PBKDF2-SHA256(code, salt || ":" || index, KDF.Iterations, KDF.Length).
	Digest string `json:"digest"`
	// QR is the slot QR (TQ4:...): show it on the device's screen.
	QR string `json:"qr"`
	// QRTerminal is the same QR drawn with Unicode half blocks, lines
	// separated by "\n", for a terminal (empty when it could not be drawn).
	QRTerminal string `json:"qrTerminal,omitempty"`
}

// OfflineDevicePack is a device's next offline sign-ins for one person.
// Nothing in it can produce a code.
type OfflineDevicePack struct {
	// Scope is the scope as Touchque stored it (ID in lower case, Name
	// cleaned) with its Epoch.
	Scope   OfflineDeviceScope `json:"scope"`
	Account string             `json:"account"`
	// ValidUntil: the slots are not valid after this time.
	ValidUntil time.Time `json:"validUntil"`
	// CodeLength is the number of characters of a slot's code (10).
	CodeLength int                 `json:"codeLength"`
	KDF        OfflineDeviceKDF    `json:"kdf"`
	Slots      []OfflineDeviceSlot `json:"slots"`
}

// IssueDevicePack asks for the next offline sign-ins of a person on one device
// that must sign them in with no network. Ask only right after a sign-in the
// person approved on the phone at that device itself, never for a remote
// session. Each slot is the slow digest of a 10-character code and a QR
// (TQ4:) only the person's phone opens. Offline, the device shows the lowest
// unused slot's QR; the person scans it with the Touchque app, approves and
// types the code (XXXXX-XXXXX); check it with VerifyDeviceCode. Indexes
// continue from the device's last pack and are never issued twice. Requires
// the workspace policies offlineSignEnabled and offlineDevicePacksEnabled
// (403 offline_device_packs_disabled); refused under a passkey-only policy
// (403 phishing_resistant_required), for a phone not enrolled for offline
// sign (409 device_not_enrolled_for_offline), for a revoked device (409
// scope_revoked) and after 12 packs an hour per person and device (429
// too_many_packs).
func (o *OfflineResource) IssueDevicePack(opts OfflineDevicePackOptions) (*OfflineDevicePack, error) {
	body := map[string]interface{}{
		"externalUsername": opts.ExternalUsername,
		"scope":            map[string]interface{}{"id": opts.Scope.ID, "name": opts.Scope.Name},
		"account":          opts.Account,
	}
	if opts.Count > 0 {
		body["count"] = opts.Count
	}
	if opts.ValidDays > 0 {
		body["validDays"] = opts.ValidDays
	}
	res, err := o.http.post("/offline/device-packs", body)
	if err != nil {
		return nil, err
	}
	out := &OfflineDevicePack{}
	if err := decodeInto(res, out); err != nil {
		return nil, err
	}
	return out, nil
}

// OfflineDeviceRevokeOptions holds the POST /offline/device-packs/revoke fields.
type OfflineDeviceRevokeOptions struct {
	// ScopeID is the device's scope id.
	ScopeID string
	// ExternalUsername: only this person's packs on the device (empty: every person's).
	ExternalUsername string
	// Reason: up to 64 characters, such as "lost", "stolen" or "reinstalled" (empty: "revoked").
	Reason string
}

// OfflineDeviceRevokeResult says how many packs (one per person on the device) were revoked.
type OfflineDeviceRevokeResult struct {
	Revoked int `json:"revoked"`
}

// RevokeDeviceScope stops a device's offline sign-ins (lost, stolen,
// reinstalled): it gets no more packs, and the person's phone refuses its
// codes once it has the list. A reinstalled device needs a new scope id.
func (o *OfflineResource) RevokeDeviceScope(opts OfflineDeviceRevokeOptions) (*OfflineDeviceRevokeResult, error) {
	body := map[string]interface{}{"scopeId": opts.ScopeID}
	if opts.ExternalUsername != "" {
		body["externalUsername"] = opts.ExternalUsername
	}
	if opts.Reason != "" {
		body["reason"] = opts.Reason
	}
	res, err := o.http.post("/offline/device-packs/revoke", body)
	if err != nil {
		return nil, err
	}
	out := &OfflineDeviceRevokeResult{}
	if err := decodeInto(res, out); err != nil {
		return nil, err
	}
	return out, nil
}

// OfflineDeviceUse is a slot the device accepted while it had no network.
type OfflineDeviceUse struct {
	Index int
	// At is when the person signed in (within the last 60 days); sent in UTC.
	At time.Time
}

// OfflineDeviceReportOptions holds the POST /offline/device-packs/report fields.
type OfflineDeviceReportOptions struct {
	ScopeID          string
	ExternalUsername string
	// Used: 1-100 slots.
	Used []OfflineDeviceUse
}

// OfflineDeviceReportResult says how many slots were recorded and how many
// were ignored (an index never issued or repeated, or a time more than 60
// days ago or in the future).
type OfflineDeviceReportResult struct {
	Recorded int `json:"recorded"`
	Ignored  int `json:"ignored"`
}

// ReportDevicePackUse sends the slots a device accepted while it had no
// network, once it is back online: Touchque writes one log row per slot with
// the time it happened (404 unknown_scope when the device has no pack for
// that person).
func (o *OfflineResource) ReportDevicePackUse(opts OfflineDeviceReportOptions) (*OfflineDeviceReportResult, error) {
	used := make([]map[string]interface{}, 0, len(opts.Used))
	for _, u := range opts.Used {
		used = append(used, map[string]interface{}{"index": u.Index, "at": u.At.UTC().Format("2006-01-02T15:04:05.000Z07:00")})
	}
	body := map[string]interface{}{"scopeId": opts.ScopeID, "externalUsername": opts.ExternalUsername, "used": used}
	res, err := o.http.post("/offline/device-packs/report", body)
	if err != nil {
		return nil, err
	}
	out := &OfflineDeviceReportResult{}
	if err := decodeInto(res, out); err != nil {
		return nil, err
	}
	return out, nil
}

const deviceCodeLength = 10

// NormalizeDeviceCode returns a typed offline sign-in code in its canonical
// form (upper case, without spaces or dashes) and true, or "" and false
// unless it is exactly 10 characters of the codes' alphabet (A-Z and 2-9
// without I and O).
func NormalizeDeviceCode(code string) (string, bool) {
	var b strings.Builder
	for i := 0; i < len(code); i++ {
		c := code[i]
		switch {
		case c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\f' || c == '\v' || c == '-':
			continue
		case c >= 'a' && c <= 'z':
			c -= 'a' - 'A'
		}
		if b.Len() == deviceCodeLength || strings.IndexByte(offlineCodeAlphabet, c) < 0 {
			return "", false
		}
		b.WriteByte(c)
	}
	if b.Len() != deviceCodeLength {
		return "", false
	}
	return b.String(), true
}

// FormatDeviceCode returns an offline sign-in code the way the phone shows
// it, "XXXXX-XXXXX", and true; "" and false unless NormalizeDeviceCode accepts it.
func FormatDeviceCode(code string) (string, bool) {
	given, ok := NormalizeDeviceCode(code)
	if !ok {
		return "", false
	}
	return given[:5] + "-" + given[5:], true
}

// VerifyDeviceCode checks the code a person typed against one slot of an
// offline sign-in pack (the pack's KDF and one of its Slots), on the device
// and with no network: PBKDF2-SHA256(code, salt || ":" || index,
// kdf.Iterations, kdf.Length) compared in constant time with the slot's
// digest. Case, spaces and dashes are ignored; anything that is not 10
// characters of the codes' alphabet is false without computing the digest,
// and so is a KDF other than pbkdf2-sha256. Check the lowest unused slot only.
// The digest takes a moment by design (600,000 iterations).
func VerifyDeviceCode(kdf OfflineDeviceKDF, slot OfflineDeviceSlot, code string) bool {
	given, ok := NormalizeDeviceCode(code)
	if !ok || (kdf.Name != "" && kdf.Name != "pbkdf2-sha256") {
		return false
	}
	if kdf.Iterations < 1 || kdf.Iterations > math.MaxInt32 || kdf.Length < 1 || slot.Index < 1 {
		return false
	}
	salt, err := base64.StdEncoding.DecodeString(slot.Salt)
	if err != nil {
		return false
	}
	want, err := base64.StdEncoding.DecodeString(slot.Digest)
	if err != nil || len(want) != kdf.Length {
		return false
	}
	got, err := pbkdf2.Key(sha256.New, given, append(salt, ":"+strconv.Itoa(slot.Index)...), kdf.Iterations, kdf.Length)
	return err == nil && subtle.ConstantTimeCompare(got, want) == 1
}
