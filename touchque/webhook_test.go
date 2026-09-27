package touchque

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"testing"
	"time"
)

const testWebhookSecret = "whsec_test"

// serverWebhook reproduces the API server: sign stableStringify(payload)
// (top-level keys sorted, no `signature`, compact, no HTML escaping) and
// deliver the body as {...payload, signature}.
func serverWebhook(t *testing.T, payload map[string]interface{}, secret string) string {
	t.Helper()
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(payload); err != nil {
		t.Fatalf("encode: %v", err)
	}
	canonical := bytes.TrimRight(buf.Bytes(), "\n")

	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(canonical)
	sig := hex.EncodeToString(mac.Sum(nil))

	withSig := map[string]interface{}{"signature": sig}
	for k, v := range payload {
		withSig[k] = v
	}
	out, err := json.Marshal(withSig)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return string(out)
}

// serverWebhookRaw signs a hand-written canonical string (top-level keys already
// sorted, `signature` absent) exactly as the server does, then delivers the body
// as {...payload, signature} with `signature` appended last. Used to exercise
// payloads with nested objects / precise numbers, where a map round-trip in the
// helper would itself sort nested keys and reformat numbers.
func serverWebhookRaw(t *testing.T, canonicalNoSig, secret string) string {
	t.Helper()
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(canonicalNoSig))
	sig := hex.EncodeToString(mac.Sum(nil))
	return canonicalNoSig[:len(canonicalNoSig)-1] + `,"signature":"` + sig + `"}`
}

func freshPayload() map[string]interface{} {
	return map[string]interface{}{
		"event":     "login.confirmed",
		"requestId": "req_1",
		"status":    "SUCCESS",
		"timestamp": time.Now().UTC().Format(time.RFC3339),
		"jti":       "jti_1",
	}
}

func newTestWebhook(t *testing.T) *WebhookResource {
	t.Helper()
	config := &Config{APIKey: "tq_auth_test123", APISecret: testWebhookSecret}
	config.sanitize()
	return newWebhookResource(config)
}

func TestWebhook_VerifiesGenuineServerSignedCallback(t *testing.T) {
	w := newTestWebhook(t)
	rawBody := serverWebhook(t, freshPayload(), testWebhookSecret)

	payload, err := w.Verify(rawBody, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if payload["requestId"] != "req_1" {
		t.Fatalf("unexpected payload: %+v", payload)
	}
}

func TestWebhook_AcceptsHeaderSignature(t *testing.T) {
	w := newTestWebhook(t)
	rawBody := serverWebhook(t, freshPayload(), testWebhookSecret)
	var decoded map[string]interface{}
	_ = json.Unmarshal([]byte(rawBody), &decoded)
	headerSig, _ := decoded["signature"].(string)

	if _, err := w.Verify(rawBody, headerSig); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestWebhook_RejectsTamperedBody(t *testing.T) {
	w := newTestWebhook(t)
	rawBody := serverWebhook(t, freshPayload(), testWebhookSecret)
	tampered := bytes.Replace([]byte(rawBody), []byte("req_1"), []byte("req_evil"), 1)

	if _, err := w.Verify(string(tampered), ""); err == nil {
		t.Fatal("expected a signature error for a tampered body")
	}
}

func TestWebhook_RejectsWrongSecret(t *testing.T) {
	w := newTestWebhook(t)
	rawBody := serverWebhook(t, freshPayload(), "not_the_secret")

	_, err := w.Verify(rawBody, "")
	if _, ok := err.(*WebhookSignatureError); !ok {
		t.Fatalf("expected *WebhookSignatureError, got %T (%v)", err, err)
	}
}

func TestWebhook_RejectsMissingSignature(t *testing.T) {
	w := newTestWebhook(t)
	body, _ := json.Marshal(freshPayload())

	if _, err := w.Verify(string(body), ""); err == nil {
		t.Fatal("expected an error when no signature is present")
	}
}

func TestWebhook_RejectsMalformedJSON(t *testing.T) {
	w := newTestWebhook(t)

	_, err := w.Verify("not json", "sig")
	if _, ok := err.(*WebhookSignatureError); !ok {
		t.Fatalf("expected *WebhookSignatureError, got %T (%v)", err, err)
	}
}

func TestWebhook_RejectsStaleTimestampAsReplay(t *testing.T) {
	w := newTestWebhook(t)
	payload := freshPayload()
	payload["timestamp"] = time.Now().Add(-1 * time.Hour).UTC().Format(time.RFC3339)
	rawBody := serverWebhook(t, payload, testWebhookSecret)

	if _, err := w.Verify(rawBody, ""); err == nil {
		t.Fatal("expected a replay/timestamp error")
	}
}

func TestWebhook_PreservesNestedObjectKeyOrderAndNumbers(t *testing.T) {
	w := newTestWebhook(t)
	// Top-level keys already sorted (context, event, requestId, riskScore,
	// status). The nested `context` is deliberately NOT sorted (z before a) and
	// carries a fractional number + a nested-nested object — the server only
	// sorts the top level and re-emits nested values verbatim (JSON.stringify).
	canonical := `{"context":{"z":1,"a":2,"inner":{"y":true,"x":false}},"event":"login.confirmed",` +
		`"requestId":"req_1","riskScore":0.25,"status":"SUCCESS"}`
	rawBody := serverWebhookRaw(t, canonical, testWebhookSecret)

	payload, err := w.Verify(rawBody, "")
	if err != nil {
		t.Fatalf("nested-object callback failed verification (canonicalize must not sort nested keys): %v", err)
	}
	ctx, ok := payload["context"].(map[string]interface{})
	if !ok || ctx["z"] != float64(1) {
		t.Fatalf("nested payload not returned intact: %+v", payload)
	}
}

func TestWebhook_PreservesHighPrecisionNumbers(t *testing.T) {
	w := newTestWebhook(t)
	// A number that float64 re-serialization would reformat (e.g. to 1.23e8).
	canonical := `{"event":"txn","ledgerBalance":123456789.123456789,"requestId":"req_9"}`
	rawBody := serverWebhookRaw(t, canonical, testWebhookSecret)

	if _, err := w.Verify(rawBody, ""); err != nil {
		t.Fatalf("high-precision number reformatted by canonicalize: %v", err)
	}
}

func TestWebhook_ErrorDoesNotLeakExpectedSignature(t *testing.T) {
	w := newTestWebhook(t)
	rawBody := serverWebhook(t, freshPayload(), "wrong")

	_, err := w.Verify(rawBody, "")
	if err == nil {
		t.Fatal("expected an error")
	}
	if bytes.Contains([]byte(err.Error()), []byte("Expected")) {
		t.Fatalf("error message leaks signing detail: %q", err.Error())
	}
}
