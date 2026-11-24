package touchque

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// radiusFake answers the RADIUS API and checks every request's signature the
// way Touchque SSO does.
func radiusFake(t *testing.T, secret string, handle func(path string, body map[string]interface{}) (int, interface{})) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		sum := sha256.Sum256(raw)
		msg := r.Method + ":" + r.URL.RequestURI() + ":" + r.Header.Get("x-timestamp") + ":" + r.Header.Get("x-nonce") + ":" + hex.EncodeToString(sum[:])
		mac := hmac.New(sha256.New, []byte(secret))
		mac.Write([]byte(msg))
		if r.Header.Get("x-signature") != hex.EncodeToString(mac.Sum(nil)) {
			t.Errorf("bad signature for %s", r.URL.Path)
			w.WriteHeader(401)
			return
		}
		var body map[string]interface{}
		_ = json.Unmarshal(raw, &body)
		status, out := handle(r.URL.Path, body)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(out)
	}))
}

func TestRadiusClientRefusesOtherKeys(t *testing.T) {
	if _, err := NewRadiusClient(&Config{APIKey: "tq_live_x", APISecret: "s", BaseURL: "http://localhost:1"}); err == nil {
		t.Fatal("a partner API key must not make a RADIUS client")
	}
	if _, err := NewRadiusClient(&Config{APIKey: "tq_rad_x", APISecret: "s", BaseURL: "http://sso.example.com"}); err == nil {
		t.Fatal("plaintext http to a remote host must be refused")
	}
}

func TestRadiusClientFlow(t *testing.T) {
	secret := "radius-secret"
	srv := radiusFake(t, secret, func(path string, body map[string]interface{}) (int, interface{}) {
		switch path {
		case "/sso/radius/v1/config":
			if body["version"] != "0.1.0" || body["clients"].(float64) != 2 {
				t.Errorf("config body: %v", body)
			}
			return 200, map[string]interface{}{"app": map[string]interface{}{
				"id": "a1", "name": "Office VPN", "status": "active", "vendor": "fortigate", "primaryAuth": "directory",
				"challenge": "number", "allowedNas": []string{"10.0.0.1"}, "organization": "Acme",
			}}
		case "/sso/radius/v1/auth":
			if body["username"] != "jdoe" || body["primaryVerified"] != true {
				t.Errorf("auth body: %v", body)
			}
			nas := body["nas"].(map[string]interface{})
			if nas["ip"] != "10.0.0.1" {
				t.Errorf("nas: %v", nas)
			}
			return 200, map[string]interface{}{"decision": "challenge", "transactionId": "tx/1", "number": "47", "caseCode": "K7P-2QX", "expiresIn": 120}
		case "/sso/radius/v1/transactions/tx%2F1/wait", "/sso/radius/v1/transactions/tx/1/wait":
			if body["waitMs"].(float64) != 20000 {
				t.Errorf("waitMs: %v", body["waitMs"])
			}
			return 200, map[string]interface{}{"decision": "accept", "email": "jdoe@acme.test"}
		case "/sso/radius/v1/transactions/tx%2F1/passcode", "/sso/radius/v1/transactions/tx/1/passcode":
			return 200, map[string]interface{}{"decision": "reject", "reason": "bad_passcode", "caseCode": "REF-USE"}
		}
		return 404, map[string]interface{}{"error": "not_found"}
	})
	defer srv.Close()

	c, err := NewRadiusClient(&Config{APIKey: "tq_rad_abc", APISecret: secret, BaseURL: srv.URL})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	app, err := c.Config(ctx, RadiusProxyInfo{Version: "0.1.0", Clients: 2})
	if err != nil || app.Name != "Office VPN" || app.Challenge != "number" || len(app.AllowedNAS) != 1 {
		t.Fatalf("config: %+v %v", app, err)
	}
	d, err := c.Authenticate(ctx, RadiusAuthRequest{Username: "jdoe", PrimaryVerified: true, NAS: RadiusNAS{IP: "10.0.0.1"}})
	if err != nil || d.Decision != "challenge" || d.Number != "47" || d.CaseCode != "K7P-2QX" || d.ExpiresIn != 120 {
		t.Fatalf("auth: %+v %v", d, err)
	}
	d, err = c.Wait(ctx, d.TransactionID, 20*time.Second)
	if err != nil || d.Decision != "accept" || d.Email != "jdoe@acme.test" {
		t.Fatalf("wait: %+v %v", d, err)
	}
	d, err = c.Passcode(ctx, "tx/1", "123456")
	if err != nil || d.Decision != "reject" || d.Reason != "bad_passcode" {
		t.Fatalf("passcode: %+v %v", d, err)
	}
}

func TestRadiusClientAPIError(t *testing.T) {
	srv := radiusFake(t, "s", func(path string, body map[string]interface{}) (int, interface{}) {
		return 401, map[string]interface{}{"error": "invalid_credential", "message": "Unknown proxy key"}
	})
	defer srv.Close()
	c, err := NewRadiusClient(&Config{APIKey: "tq_rad_abc", APISecret: "s", BaseURL: srv.URL})
	if err != nil {
		t.Fatal(err)
	}
	_, err = c.Authenticate(context.Background(), RadiusAuthRequest{Username: "x"})
	apiErr, ok := err.(*APIError)
	if !ok || apiErr.StatusCode != 401 || !strings.Contains(apiErr.Message, "invalid_credential") {
		t.Fatalf("want a 401 APIError, got %v", err)
	}
}

func TestRadiusClientTerminalQR(t *testing.T) {
	secret := "radius-secret"
	srv := radiusFake(t, secret, func(path string, body map[string]interface{}) (int, interface{}) {
		switch path {
		case "/sso/radius/v1/auth":
			if body["terminalQr"] != true {
				t.Errorf("auth body without terminalQr: %v", body)
			}
			return 200, map[string]interface{}{"decision": "challenge", "transactionId": "tx1", "number": "47", "qr": "TQ3:ABC", "qrTerminal": "█▀\n▄ ", "expiresIn": 180}
		case "/sso/radius/v1/transactions/tx1/passcode":
			return 200, map[string]interface{}{"decision": "retry", "transactionId": "tx1", "reason": "bad_passcode", "attemptsLeft": 2}
		}
		t.Errorf("unexpected path %s", path)
		return 404, map[string]interface{}{}
	})
	defer srv.Close()
	rc, err := NewRadiusClient(&Config{APIKey: "tq_rad_x", APISecret: secret, BaseURL: srv.URL})
	if err != nil {
		t.Fatal(err)
	}
	d, err := rc.Authenticate(context.Background(), RadiusAuthRequest{Username: "jdoe", TerminalQR: true})
	if err != nil {
		t.Fatal(err)
	}
	if d.QR != "TQ3:ABC" || d.QRTerminal != "█▀\n▄ " || d.Number != "47" {
		t.Fatalf("decision: %+v", d)
	}
	d, err = rc.Passcode(context.Background(), "tx1", "ABCDEFG")
	if err != nil {
		t.Fatal(err)
	}
	if d.Decision != "retry" || d.AttemptsLeft != 2 {
		t.Fatalf("retry: %+v", d)
	}
}

func TestRadiusClientOfflinePacks(t *testing.T) {
	secret := "radius-secret"
	srv := radiusFake(t, secret, func(path string, body map[string]interface{}) (int, interface{}) {
		switch path {
		case "/sso/radius/v1/offline-packs":
			if body["machineId"] != "0f1e2d3c4b5a6978" || body["have"].(float64) != 3 {
				t.Errorf("pack body: %v", body)
			}
			return 200, map[string]interface{}{"email": "jane@acme.test", "account": `ORNEK\jane`, "scope": map[string]interface{}{"id": "pc-0f1e2d3c4b5a6978", "name": "LAPTOP", "epoch": "0123456789abcdef"},
				"validUntil": "2026-11-26T10:00:00.000Z", "codeLength": 10, "kdf": map[string]interface{}{"name": "pbkdf2-sha256", "iterations": 600000, "length": 16},
				"slots": []map[string]interface{}{{"index": 4, "salt": "c2FsdA==", "digest": "ZGlnZXN0", "qr": "TQ4:X", "qrTerminal": "█"}}}
		case "/sso/radius/v1/offline-packs/sync":
			return 200, map[string]interface{}{"revoked": false, "packs": []map[string]interface{}{{"email": "jane@acme.test", "action": "keep"}}}
		}
		t.Errorf("unexpected path %s", path)
		return 404, map[string]interface{}{}
	})
	defer srv.Close()
	rc, err := NewRadiusClient(&Config{APIKey: "tq_rad_x", APISecret: secret, BaseURL: srv.URL})
	if err != nil {
		t.Fatal(err)
	}
	p, err := rc.OfflinePack(context.Background(), RadiusOfflinePackRequest{TransactionID: "tx1", MachineID: "0f1e2d3c4b5a6978", Computer: "LAPTOP", Account: `ORNEK\jane`, Have: 3})
	if err != nil {
		t.Fatal(err)
	}
	if p.Scope.Epoch != "0123456789abcdef" || p.KDF.Iterations != 600000 || len(p.Slots) != 1 || p.Slots[0].Index != 4 || p.ValidUntil.Year() != 2026 {
		t.Fatalf("pack: %+v", p)
	}
	res, err := rc.OfflinePackSync(context.Background(), RadiusOfflineSyncRequest{MachineID: "0f1e2d3c4b5a6978", Packs: []RadiusOfflinePackState{{Email: "jane@acme.test", Used: []RadiusOfflineUse{{Index: 4, At: time.Now()}}}}})
	if err != nil || res.Revoked || len(res.Packs) != 1 || res.Packs[0].Action != "keep" {
		t.Fatalf("sync: %+v %v", res, err)
	}
}
