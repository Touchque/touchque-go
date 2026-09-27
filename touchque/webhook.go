package touchque

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"math"
	"sort"
	"time"
)

// defaultWebhookToleranceSeconds is the replay window: a callback whose
// signed `timestamp` is further than this from now is rejected.
const defaultWebhookToleranceSeconds = 300

// WebhookResource handles incoming webhook signature verification.
type WebhookResource struct {
	config *Config
}

func newWebhookResource(config *Config) *WebhookResource {
	return &WebhookResource{config: config}
}

// jsonEncodeNoHTML mirrors JSON.stringify of a single value: compact, and
// without Go's default <, >, & escaping.
func jsonEncodeNoHTML(v interface{}) (string, error) {
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return "", err
	}
	return string(bytes.TrimRight(b.Bytes(), "\n")), nil
}

// canonicalize reproduces the API server's canonical JSON stringification:
// drop the `signature` field, sort the TOP-LEVEL keys only, and re-emit each
// value's bytes verbatim. Nested objects keep their original key order and
// numbers keep their exact formatting — matching JSON.stringify, which the
// server used to build the payload. (Decoding into a map and re-encoding, as an
// earlier version did, sorts keys at every depth and reformats every number.)
func canonicalize(rawBody []byte) (string, error) {
	var top map[string]json.RawMessage
	if err := json.Unmarshal(rawBody, &top); err != nil {
		return "", err
	}

	keys := make([]string, 0, len(top))
	for k := range top {
		if k == "signature" {
			continue
		}
		keys = append(keys, k)
	}
	sort.Strings(keys)

	var b bytes.Buffer
	b.WriteByte('{')
	for i, k := range keys {
		if i > 0 {
			b.WriteByte(',')
		}
		ek, err := jsonEncodeNoHTML(k)
		if err != nil {
			return "", err
		}
		b.WriteString(ek)
		b.WriteByte(':')
		// Elide any insignificant whitespace (e.g. a pretty-printed body from a
		// proxy) without touching string/number contents.
		if err := json.Compact(&b, top[k]); err != nil {
			return "", err
		}
	}
	b.WriteByte('}')
	return b.String(), nil
}

// Verify checks the signature of an incoming webhook and returns the decoded
// payload. `signature` is the x-signature header value; pass "" to fall back
// to the `signature` field carried inside the body.
//
// An optional toleranceSeconds overrides the 300s replay window (parity with
// the Node/PHP/Python SDKs); pass 0 to disable the freshness check.
func (w *WebhookResource) Verify(rawBody string, signature string, toleranceSeconds ...int) (map[string]interface{}, error) {
	tolerance := defaultWebhookToleranceSeconds
	if len(toleranceSeconds) > 0 {
		tolerance = toleranceSeconds[0]
	}
	var payload map[string]interface{}
	if err := json.Unmarshal([]byte(rawBody), &payload); err != nil {
		return nil, &WebhookSignatureError{Message: "Invalid JSON payload"}
	}

	provided := signature
	if provided == "" {
		if s, ok := payload["signature"].(string); ok {
			provided = s
		}
	}
	if provided == "" {
		return nil, &WebhookSignatureError{Message: "No signature provided"}
	}

	canonical, err := canonicalize([]byte(rawBody))
	if err != nil {
		return nil, &WebhookSignatureError{Message: "Could not canonicalize payload"}
	}

	mac := hmac.New(sha256.New, []byte(w.config.APISecret))
	mac.Write([]byte(canonical))
	expected := hex.EncodeToString(mac.Sum(nil))

	// Do NOT include the expected signature in the error — a caller that
	// surfaces the message would hand an attacker a signing oracle.
	if !hmac.Equal([]byte(expected), []byte(provided)) {
		return nil, &WebhookSignatureError{Message: "Invalid webhook signature"}
	}

	if tolerance > 0 {
		if ts, ok := payload["timestamp"].(string); ok {
			if parsed, perr := time.Parse(time.RFC3339, ts); perr == nil {
				if math.Abs(time.Since(parsed).Seconds()) > float64(tolerance) {
					return nil, &WebhookSignatureError{Message: "Webhook timestamp is outside the allowed window"}
				}
			}
		}
	}

	return payload, nil
}
