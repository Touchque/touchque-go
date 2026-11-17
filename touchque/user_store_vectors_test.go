package touchque

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
	"unicode/utf8"
)

// fixtures/user-store-vectors.json: Touchque Login user-store requests (user_store.verify_password,
// user_store.get_user, user_store.ping) exactly as the backend sends them, recorded from its own code
// (its user-store requests and webhook canonicalisation), shared with every server SDK.
// They hold what JavaScript's JSON.stringify writes: unpaired surrogates as lowercase escapes, U+2028,
// U+2029, <>& and non-ASCII raw, NUL and other control characters escaped, quotes and backslashes.
type userStoreVector struct {
	Name            string                 `json:"name"`
	Event           string                 `json:"event"`
	Valid           bool                   `json:"valid"`
	Note            string                 `json:"note"`
	Secret          string                 `json:"secret"`
	Body            string                 `json:"body"`
	XSignature      string                 `json:"x_signature"`
	Canonical       string                 `json:"canonical"`
	ExpectedPayload map[string]interface{} `json:"expected_payload"`
}

func readUserStoreVectors(t *testing.T) []userStoreVector {
	t.Helper()
	var fx struct {
		Vectors []userStoreVector `json:"vectors"`
	}
	readFixture(t, "user-store-vectors.json", &fx)
	if len(fx.Vectors) == 0 {
		t.Fatal("no user-store vectors")
	}
	return fx.Vectors
}

func TestUserStoreVectors(t *testing.T) {
	valid, refused := 0, 0
	for _, v := range readUserStoreVectors(t) {
		if v.Valid {
			valid++
		} else {
			refused++
		}
		t.Run(v.Name, func(t *testing.T) {
			// The string the backend signed, built from the raw text.
			canonical, err := canonicalize([]byte(v.Body))
			if err != nil {
				t.Fatalf("canonicalize: %v", err)
			}
			if canonical != v.Canonical {
				t.Fatalf("canonical mismatch\n got: %s\nwant: %s", canonical, v.Canonical)
			}
			mac := hmac.New(sha256.New, []byte(v.Secret))
			mac.Write([]byte(canonical))
			if signed := hex.EncodeToString(mac.Sum(nil)) == v.XSignature; signed != v.Valid {
				t.Fatalf("HMAC over the canonical matches x-signature: %v, want %v", signed, v.Valid)
			}

			c := NewClient(&Config{APIKey: "tq_test_key", APISecret: v.Secret, BaseURL: "https://api.touchque.com"})
			// The x-signature header, then "" (the body's own signature field). The timestamps are
			// fixed in the past, so 0 turns the freshness window off.
			for _, header := range []string{v.XSignature, ""} {
				payload, err := c.Webhook.Verify(v.Body, header, 0)
				if !v.Valid {
					var sigErr *WebhookSignatureError
					if !errors.As(err, &sigErr) || payload != nil {
						t.Fatalf("header %q: want a *WebhookSignatureError, got %v %v", header, payload, err)
					}
					continue
				}
				if err != nil {
					t.Fatalf("header %q: %v", header, err)
				}
				if !reflect.DeepEqual(payload, v.ExpectedPayload) {
					t.Fatalf("header %q: payload\n got: %#v\nwant: %#v", header, payload, v.ExpectedPayload)
				}
				// Every unpaired surrogate is U+FFFD: each string is valid UTF-8, so it can be read
				// (a password checked) and written out again.
				for k, val := range payload {
					if s, ok := val.(string); ok && !utf8.ValidString(s) {
						t.Fatalf("%s is not valid UTF-8: %q", k, s)
					}
				}
				if _, err := json.Marshal(payload); err != nil {
					t.Fatalf("payload does not encode: %v", err)
				}
			}
		})
	}
	if valid == 0 || refused == 0 {
		t.Fatalf("want valid and refused vectors, got %d and %d", valid, refused)
	}
}

// esc is the JSON escape of a UTF-16 code unit (4 hex digits), as it is written in a body.
func esc(unit string) string { return "\\" + "u" + unit }

// A signed user-store request fails once its text changes after signing, also when the change leaves
// the decoded payload as it was (another unpaired surrogate, or an escape of the same character), and
// with a signature one character off.
func TestUserStoreVectorsTampered(t *testing.T) {
	edits := []struct {
		vector, from, to string
		// samePayload: the changed body decodes to the very payload the genuine one does.
		samePayload bool
	}{
		{"verify_password_unpaired_high_surrogates", esc("d800"), esc("d801"), true},
		{"verify_password_unpaired_low_surrogates", esc("dc00"), esc("fffd"), true},
		{"verify_password_line_separators", string(rune(0x2028)), string(rune(0x2029)), false},
		{"verify_password_nul_and_u0001", esc("0000"), esc("0002"), false},
		{"verify_password_quotes_backslashes", `end\\"`, `end\\\\"`, false},
		{"verify_password_everything", "<>&", esc("003c") + ">&", true},
		{"get_user_special_email", esc("dfff"), esc("dffe"), true},
	}
	vectors := map[string]userStoreVector{}
	for _, v := range readUserStoreVectors(t) {
		vectors[v.Name] = v
	}
	for _, e := range edits {
		v, ok := vectors[e.vector]
		if !ok || !v.Valid {
			t.Fatalf("%s: no such valid vector", e.vector)
		}
		c := NewClient(&Config{APIKey: "tq_test_key", APISecret: v.Secret, BaseURL: "https://api.touchque.com"})
		if _, err := c.Webhook.Verify(v.Body, v.XSignature, 0); err != nil {
			t.Fatalf("%s: %v", e.vector, err)
		}
		if !strings.Contains(v.Body, e.from) {
			t.Fatalf("%s: %q is not in the body", e.vector, e.from)
		}
		tampered := strings.Replace(v.Body, e.from, e.to, 1)
		if e.samePayload {
			var decoded map[string]interface{}
			if err := json.Unmarshal([]byte(tampered), &decoded); err != nil || !reflect.DeepEqual(decoded, v.ExpectedPayload) {
				t.Fatalf("%s: the changed body should decode to the same payload: %v %v", e.vector, decoded, err)
			}
		}
		var sigErr *WebhookSignatureError
		if _, err := c.Webhook.Verify(tampered, v.XSignature, 0); !errors.As(err, &sigErr) {
			t.Fatalf("%s changed (%q to %q): %v", e.vector, e.from, e.to, err)
		}
		if _, err := c.Webhook.Verify(tampered, "", 0); !errors.As(err, &sigErr) {
			t.Fatalf("%s changed, body signature: %v", e.vector, err)
		}
		flipped := v.XSignature[:len(v.XSignature)-1] + "0"
		if strings.HasSuffix(v.XSignature, "0") {
			flipped = v.XSignature[:len(v.XSignature)-1] + "1"
		}
		if _, err := c.Webhook.Verify(v.Body, flipped, 0); !errors.As(err, &sigErr) {
			t.Fatalf("%s with a wrong signature: %v", e.vector, err)
		}
	}
}
