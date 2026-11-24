package touchque

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

// fakeDeviceCode is the shared fake API's code of offline sign-in slot index
// (its packs use 1,000 iterations).
func fakeDeviceCode(index int) string {
	const a = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
	return "ABCDEFGH" + string(a[index%32]) + string(a[(index/32)%32])
}

func TestOffline_IssueDevicePackPostsThePersonTheDeviceAndTheAccount(t *testing.T) {
	var seen []map[string]interface{}
	client, closeFn := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		var body map[string]interface{}
		_ = json.NewDecoder(r.Body).Decode(&body)
		seen = append(seen, body)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"scope": map[string]interface{}{"id": "pc-1", "name": "LAPTOP-JANE", "epoch": "0123456789abcdef"}, "account": `ACME\jane`,
			"validUntil": "2026-11-26T10:00:00.000Z", "codeLength": 10, "kdf": map[string]interface{}{"name": "pbkdf2-sha256", "iterations": 600000, "length": 16},
			"slots": []interface{}{map[string]interface{}{"index": 4294967295, "salt": "AAAA", "digest": "BBBB", "qr": "TQ4:X", "qrTerminal": nil}},
		})
	})
	defer closeFn()

	scope := OfflineDeviceScope{ID: "pc-1", Name: "LAPTOP-JANE"}
	pack, err := client.Offline.IssueDevicePack(OfflineDevicePackOptions{ExternalUsername: "jane@acme.com", Scope: scope, Account: `ACME\jane`})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.Offline.IssueDevicePack(OfflineDevicePackOptions{ExternalUsername: "jane@acme.com", Scope: scope, Account: `ACME\jane`, Count: 5, ValidDays: 7}); err != nil {
		t.Fatal(err)
	}
	want := []map[string]interface{}{
		{"externalUsername": "jane@acme.com", "scope": map[string]interface{}{"id": "pc-1", "name": "LAPTOP-JANE"}, "account": `ACME\jane`},
		{"externalUsername": "jane@acme.com", "scope": map[string]interface{}{"id": "pc-1", "name": "LAPTOP-JANE"}, "account": `ACME\jane`, "count": float64(5), "validDays": float64(7)},
	}
	if !reflect.DeepEqual(seen, want) {
		t.Fatalf("bodies = %+v", seen)
	}
	if pack.Scope.Epoch != "0123456789abcdef" || !pack.ValidUntil.Equal(time.Date(2026, 11, 26, 10, 0, 0, 0, time.UTC)) || pack.KDF.Iterations != 600000 ||
		len(pack.Slots) != 1 || pack.Slots[0].Index != 4294967295 || pack.Slots[0].QR != "TQ4:X" || pack.Slots[0].QRTerminal != "" {
		t.Fatalf("unexpected pack: %+v", pack)
	}
}

func TestOffline_RevokeAndReportDevicePacksPostTheScopeIDAndTimesInUTC(t *testing.T) {
	var seen []map[string]interface{}
	client, closeFn := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		var body map[string]interface{}
		_ = json.NewDecoder(r.Body).Decode(&body)
		seen = append(seen, map[string]interface{}{"path": r.URL.Path, "body": body})
		if strings.HasSuffix(r.URL.Path, "/report") {
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"recorded": 2, "ignored": 0})
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"revoked": 1})
	})
	defer closeFn()

	if r, err := client.Offline.RevokeDeviceScope(OfflineDeviceRevokeOptions{ScopeID: "pc-1"}); err != nil || r.Revoked != 1 {
		t.Fatalf("revoke = %+v, %v", r, err)
	}
	if _, err := client.Offline.RevokeDeviceScope(OfflineDeviceRevokeOptions{ScopeID: "pc-1", ExternalUsername: "jane@acme.com", Reason: "lost"}); err != nil {
		t.Fatal(err)
	}
	istanbul := time.FixedZone("TRT", 3*3600)
	rep, err := client.Offline.ReportDevicePackUse(OfflineDeviceReportOptions{ScopeID: "pc-1", ExternalUsername: "jane@acme.com", Used: []OfflineDeviceUse{
		{Index: 7, At: time.Date(2026, 11, 12, 11, 30, 0, 0, istanbul)},
		{Index: 8, At: time.Date(2026, 11, 12, 9, 0, 0, 123456789, time.UTC)},
	}})
	if err != nil || rep.Recorded != 2 || rep.Ignored != 0 {
		t.Fatalf("report = %+v, %v", rep, err)
	}
	want := []map[string]interface{}{
		{"path": "/offline/device-packs/revoke", "body": map[string]interface{}{"scopeId": "pc-1"}},
		{"path": "/offline/device-packs/revoke", "body": map[string]interface{}{"scopeId": "pc-1", "externalUsername": "jane@acme.com", "reason": "lost"}},
		{"path": "/offline/device-packs/report", "body": map[string]interface{}{"scopeId": "pc-1", "externalUsername": "jane@acme.com", "used": []interface{}{
			map[string]interface{}{"index": float64(7), "at": "2026-11-12T08:30:00.000Z"},
			map[string]interface{}{"index": float64(8), "at": "2026-11-12T09:00:00.123Z"},
		}}},
	}
	if !reflect.DeepEqual(seen, want) {
		t.Fatalf("calls = %+v", seen)
	}
}

func TestOffline_DeviceCodeHelpersFollowTheSharedVectors(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "fixtures", "offline-device-vectors.json"))
	if err != nil {
		t.Fatal(err)
	}
	var v struct {
		Codes []struct {
			ExpectedCode string `json:"expectedCode"`
		} `json:"codes"`
		SlotQR struct {
			ExpectedCode      string `json:"expectedCode"`
			ExpectedFormatted string `json:"expectedFormatted"`
		} `json:"slotQr"`
		Digest struct {
			Code              string           `json:"code"`
			Index             int              `json:"index"`
			SaltHex           string           `json:"saltHex"`
			KDF               OfflineDeviceKDF `json:"kdf"`
			ExpectedDigestHex string           `json:"expectedDigestHex"`
		} `json:"digest"`
		Normalize []struct {
			Input    string  `json:"input"`
			Expected *string `json:"expected"`
		} `json:"normalize"`
	}
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	for _, c := range v.Normalize {
		got, ok := NormalizeDeviceCode(c.Input)
		if (c.Expected == nil && ok) || (c.Expected != nil && (!ok || got != *c.Expected)) {
			t.Fatalf("NormalizeDeviceCode(%q) = %q %v", c.Input, got, ok)
		}
	}
	for _, c := range v.Codes {
		if got, ok := NormalizeDeviceCode(c.ExpectedCode); !ok || got != c.ExpectedCode {
			t.Fatalf("NormalizeDeviceCode(%q) = %q %v", c.ExpectedCode, got, ok)
		}
	}
	if got, ok := FormatDeviceCode(v.SlotQR.ExpectedCode); !ok || got != v.SlotQR.ExpectedFormatted {
		t.Fatalf("FormatDeviceCode = %q %v", got, ok)
	}
	if got, ok := FormatDeviceCode(" 5kmy9 tpzaq\n"); !ok || got != "5KMY9-TPZAQ" {
		t.Fatalf("FormatDeviceCode with spaces = %q %v", got, ok)
	}
	if _, ok := FormatDeviceCode("5KMY9-TPZA"); ok {
		t.Fatal("a 9-character code was formatted")
	}

	d := v.Digest
	salt, _ := hex.DecodeString(d.SaltHex)
	digest, _ := hex.DecodeString(d.ExpectedDigestHex)
	slot := OfflineDeviceSlot{Index: d.Index, Salt: base64.StdEncoding.EncodeToString(salt), Digest: base64.StdEncoding.EncodeToString(digest)}
	if !VerifyDeviceCode(d.KDF, slot, d.Code) || !VerifyDeviceCode(d.KDF, slot, strings.ToLower(v.SlotQR.ExpectedFormatted)) {
		t.Fatal("the vector's code was refused")
	}
	if VerifyDeviceCode(d.KDF, slot, "PDG4MSATZB") {
		t.Fatal("another slot's code was accepted")
	}
	next := slot
	next.Index++
	if VerifyDeviceCode(d.KDF, next, d.Code) {
		t.Fatal("the code was accepted for another index")
	}
	scrypt, longer := d.KDF, d.KDF
	scrypt.Name, longer.Length = "scrypt", 32
	badSalt := slot
	badSalt.Salt = "not base64!"
	if VerifyDeviceCode(scrypt, slot, d.Code) || VerifyDeviceCode(longer, slot, d.Code) || VerifyDeviceCode(d.KDF, badSalt, d.Code) {
		t.Fatal("a malformed KDF or slot was accepted")
	}
}

func TestOffline_VerifyDeviceCodeRefusesAMalformedCodeWithoutComputing(t *testing.T) {
	// A billion iterations would take minutes: an answer in time means nothing was computed.
	slow := OfflineDeviceKDF{Name: "pbkdf2-sha256", Iterations: 1_000_000_000, Length: 16}
	zero := base64.StdEncoding.EncodeToString(make([]byte, 16))
	slot := OfflineDeviceSlot{Index: 7, Salt: zero, Digest: zero}
	started := time.Now()
	for _, typed := range []string{"", "5KMY9TPZA", "5KMY9TPZAQ1", "ABCDEFGHI0", "ABCDEFGHIO", "5KMY9_TPZAQ", "5KMY9TPZAÉ"} {
		if VerifyDeviceCode(slow, slot, typed) {
			t.Fatalf("%q was accepted", typed)
		}
	}
	if time.Since(started) > time.Second {
		t.Fatal("a malformed code was computed")
	}
}

func TestOffline_DevicePacksAgainstTheFakeAPI(t *testing.T) {
	fake := startFakeAPI(t)
	defer fake.close()
	c := fake.client(t)
	fake.link("jane@acme.com")
	scope := OfflineDeviceScope{ID: "pc-0f1e2d3c4b5a6978", Name: "LAPTOP-JANE"}

	pack, err := c.Offline.IssueDevicePack(OfflineDevicePackOptions{ExternalUsername: "jane@acme.com", Scope: scope, Account: `ACME\jane`, Count: 3})
	if err != nil {
		t.Fatal(err)
	}
	calls := callsTo(fake, "/offline/device-packs")
	if body := calls[len(calls)-1]["body"]; !reflect.DeepEqual(body, map[string]interface{}{
		"externalUsername": "jane@acme.com", "scope": map[string]interface{}{"id": scope.ID, "name": scope.Name}, "account": `ACME\jane`, "count": float64(3),
	}) {
		t.Fatalf("unexpected body: %+v", body)
	}
	if len(pack.Slots) != 3 || pack.Slots[0].Index != 1 || pack.Slots[2].Index != 3 || pack.Scope.Epoch != "0123456789abcdef" || pack.CodeLength != 10 ||
		pack.KDF.Iterations != 1000 || pack.Slots[0].QR != "TQ4:SLOT1" || !pack.ValidUntil.After(time.Now()) {
		t.Fatalf("unexpected pack: %+v", pack)
	}
	formatted, _ := FormatDeviceCode(fakeDeviceCode(1))
	if !VerifyDeviceCode(pack.KDF, pack.Slots[0], strings.ToLower(formatted)) || VerifyDeviceCode(pack.KDF, pack.Slots[0], fakeDeviceCode(2)) ||
		!VerifyDeviceCode(pack.KDF, pack.Slots[1], fakeDeviceCode(2)) {
		t.Fatal("the slot codes did not check out")
	}
	// The next pack continues the indexes.
	again, err := c.Offline.IssueDevicePack(OfflineDevicePackOptions{ExternalUsername: "jane@acme.com", Scope: scope, Account: `ACME\jane`, Count: 2})
	if err != nil || len(again.Slots) != 2 || again.Slots[0].Index != 4 {
		t.Fatalf("second pack = %+v, %v", again, err)
	}

	now := time.Now()
	rep, err := c.Offline.ReportDevicePackUse(OfflineDeviceReportOptions{ScopeID: scope.ID, ExternalUsername: "jane@acme.com", Used: []OfflineDeviceUse{{Index: 1, At: now}, {Index: 99, At: now}}})
	if err != nil || rep.Recorded != 1 || rep.Ignored != 1 {
		t.Fatalf("report = %+v, %v", rep, err)
	}
	if _, err := c.Offline.ReportDevicePackUse(OfflineDeviceReportOptions{ScopeID: "pc-other", ExternalUsername: "jane@acme.com", Used: []OfflineDeviceUse{{Index: 1, At: now}}}); err == nil || err.(*APIError).StatusCode != 404 {
		t.Fatalf("expected 404 unknown_scope, got %v", err)
	}

	rev, err := c.Offline.RevokeDeviceScope(OfflineDeviceRevokeOptions{ScopeID: scope.ID, Reason: "lost"})
	if err != nil || rev.Revoked != 1 {
		t.Fatalf("revoke = %+v, %v", rev, err)
	}
	calls = callsTo(fake, "/offline/device-packs/revoke")
	if body := calls[len(calls)-1]["body"]; !reflect.DeepEqual(body, map[string]interface{}{"scopeId": scope.ID, "reason": "lost"}) {
		t.Fatalf("unexpected revoke body: %+v", body)
	}
	for _, tc := range []struct {
		user   string
		status int
	}{{"jane@acme.com", 409}, {"nobody@acme.com", 404}} {
		_, err := c.Offline.IssueDevicePack(OfflineDevicePackOptions{ExternalUsername: tc.user, Scope: scope, Account: `ACME\jane`})
		if apiErr, ok := err.(*APIError); !ok || apiErr.StatusCode != tc.status {
			t.Fatalf("%s: expected %d, got %v", tc.user, tc.status, err)
		}
	}
	fake.opts(map[string]interface{}{"devicePacksDisabled": true})
	_, err = c.Offline.IssueDevicePack(OfflineDevicePackOptions{ExternalUsername: "jane@acme.com", Scope: OfflineDeviceScope{ID: "pc-2", Name: "KIOSK"}, Account: "kiosk"})
	if apiErr, ok := err.(*APIError); !ok || apiErr.StatusCode != 403 {
		t.Fatalf("expected 403 offline_device_packs_disabled, got %v", err)
	}
}
