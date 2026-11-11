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
