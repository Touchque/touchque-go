package touchque

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"regexp"
	"testing"
)

// QR pairing against the shared fake API: register, the QR's text and hash,
// the phone's scan, a request for the phone that scanned, and refusals. Same
// scenarios as the Node SDK's QrPairings tests.

const qrThumb = "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs"

func storedPairing(t *testing.T, api *fakeAPI) map[string]interface{} {
	t.Helper()
	resp, err := http.Get(api.baseURL + "/__test/qr-pairings")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var all []map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&all); err != nil || len(all) == 0 {
		t.Fatalf("pairings: %v %v", all, err)
	}
	return all[len(all)-1]
}

func TestQRPairingCreateScanThenAskThePhoneThatScanned(t *testing.T) {
	api := startFakeAPI(t)
	defer api.close()
	api.link("ayse@acme.com")
	tq := api.client(t)
	ctx := context.Background()
	p, err := tq.QRPairings.Create(ctx, CreateQRPairingOptions{KeyThumbprint: qrThumb, ClientIP: "203.0.113.7", UserAgent: "Mozilla/5.0", Browser: "Chrome 155", OS: "macOS 15"})
	if err != nil {
		t.Fatal(err)
	}
	if p.URI != QRPairingURI(p.PairingID, p.Nonce, qrThumb) || !regexp.MustCompile(`^touchque://pair-browser\?v=1&p=[\w-]{22}&n=[\w-]{43}&k=[\w-]{43}$`).MatchString(p.URI) {
		t.Fatalf("uri = %s", p.URI)
	}
	sum := sha256.Sum256([]byte(p.Nonce))
	if storedPairing(t, api)["nonceHash"] != base64.RawURLEncoding.EncodeToString(sum[:]) {
		t.Fatal("nonce hash")
	}
	if got, _ := tq.QRPairings.Get(ctx, p.PairingID); got.State != "waiting" {
		t.Fatalf("state = %+v", got)
	}
	_, err = tq.Login.RequestWithOptions(LoginRequestOptions{ExternalUsername: "ayse@acme.com", Type: "LOGIN", QRPairing: p.PairingID})
	var apiErr *APIError
	if !errors.As(err, &apiErr) || apiErr.Code != "pairing_not_confirmed" {
		t.Fatalf("unconfirmed = %v", err)
	}

	api.call("/__test/qr-scan", map[string]interface{}{"id": p.PairingID, "user": "ayse@acme.com"})
	seen, err := tq.QRPairings.Get(ctx, p.PairingID)
	if err != nil || seen.State != "confirmed" || seen.ExternalUsername != "ayse@acme.com" || seen.Proximity == nil || len(seen.Proximity.Warnings) != 0 {
		t.Fatalf("scanned = %+v, %v", seen, err)
	}
	req, err := tq.Login.RequestWithOptions(LoginRequestOptions{ExternalUsername: "ayse@acme.com", Type: "LOGIN", QRPairing: p.PairingID})
	if err != nil {
		t.Fatal(err)
	}
	after, _ := tq.QRPairings.Get(ctx, p.PairingID)
	if after.State != "requested" || after.RequestID == nil || *after.RequestID != req.RequestID {
		t.Fatalf("after = %+v, request %s", after, req.RequestID)
	}
}

func TestQRPairingRefuseAfterTheScanAndChecksBeforeTheCall(t *testing.T) {
	api := startFakeAPI(t)
	defer api.close()
	api.link("ayse@acme.com")
	tq := api.client(t)
	ctx := context.Background()
	p, err := tq.QRPairings.Create(ctx, CreateQRPairingOptions{KeyThumbprint: qrThumb, TTLSeconds: 60})
	if err != nil {
		t.Fatal(err)
	}
	_, err = tq.QRPairings.Refuse(ctx, p.PairingID, RefuseQRPairingOptions{Reason: "policy", Message: "Not yet"})
	var apiErr *APIError
	if !errors.As(err, &apiErr) || apiErr.StatusCode != 409 || apiErr.Code != "not_open" {
		t.Fatalf("refuse before scan = %v", err)
	}
	api.call("/__test/qr-scan", map[string]interface{}{"id": p.PairingID, "user": "ayse@acme.com", "confirm": false})
	refused, err := tq.QRPairings.Refuse(ctx, p.PairingID, RefuseQRPairingOptions{Reason: "device_not_approved", Message: "Ask IT to approve this computer.", DeviceCode: "ABC-123"})
	if err != nil || refused.State != "refused" || refused.Outcome == nil || refused.Outcome.Reason != "device_not_approved" || refused.Outcome.DeviceCode == nil || *refused.Outcome.DeviceCode != "ABC-123" {
		t.Fatalf("refused = %+v, %v", refused, err)
	}
	var cfg *ConfigError
	for _, call := range []func() error{
		func() error {
			_, e := tq.QRPairings.Create(ctx, CreateQRPairingOptions{KeyThumbprint: "short"})
			return e
		},
		func() error {
			_, e := tq.QRPairings.Create(ctx, CreateQRPairingOptions{KeyThumbprint: qrThumb, TTLSeconds: 10})
			return e
		},
		func() error {
			_, e := tq.QRPairings.Refuse(ctx, p.PairingID, RefuseQRPairingOptions{Reason: "nope", Message: "x"})
			return e
		},
		func() error {
			_, e := tq.QRPairings.Refuse(ctx, p.PairingID, RefuseQRPairingOptions{Reason: "other", Message: " "})
			return e
		},
	} {
		if err := call(); !errors.As(err, &cfg) {
			t.Fatalf("want a ConfigError, got %v", err)
		}
	}
}
