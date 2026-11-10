package touchque

import (
	"context"
	"crypto/hmac"
	"crypto/pbkdf2"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"strconv"
	"testing"
	"time"
)

func TestRadiusOutageCacheSignedPageCodeAndLog(t *testing.T) {
	secret := "radius-secret"
	now := time.Now()
	step := now.Unix() / 30
	salt := []byte("0123456789abcdef")
	var digests []byte
	for s := step - 1; s <= step+2; s++ {
		d, _ := pbkdf2.Key(sha256.New, "K7P2QXA", append(append([]byte{}, salt...), []byte(":"+strconv.FormatInt(s, 10))...), 10, 4)
		digests = append(digests, d...)
		digests = append(digests, d...)
	}
	page := map[string]interface{}{
		"v": 1, "app": "a1", "policy": "offline_codes", "issuedAt": now.UTC().Format(time.RFC3339), "stepSeconds": 30, "until": step + 2,
		"domains": []string{"acme.com"}, "kdf": map[string]interface{}{"name": "pbkdf2-sha256", "iterations": 10, "length": 4},
		"members": []string{"u1"}, "users": []map[string]interface{}{{"id": "u1", "email": "jane@acme.com", "fromStep": step - 1,
			"salt": base64.StdEncoding.EncodeToString(salt), "digests": base64.StdEncoding.EncodeToString(digests)}}, "next": nil,
	}
	raw, _ := json.Marshal(page)
	payload := base64.StdEncoding.EncodeToString(raw)
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte("touchque-outage-cache.v1:" + payload))
	signed := map[string]string{"payload": payload, "signature": hex.EncodeToString(mac.Sum(nil))}
	var logged []interface{}
	srv := radiusFake(t, secret, func(path string, body map[string]interface{}) (int, interface{}) {
		switch path {
		case "/sso/radius/v1/outage-cache":
			if body["haveUntil"].(float64) != float64(step) || len(body["have"].([]interface{})) != 1 {
				t.Errorf("outage-cache body: %v", body)
			}
			return 200, signed
		case "/sso/radius/v1/outage-log":
			logged = body["events"].([]interface{})
			return 200, map[string]int{"written": len(logged)}
		}
		return 404, map[string]string{"error": "not_found"}
	})
	defer srv.Close()
	c, err := NewRadiusClient(&Config{APIKey: "tq_rad_x", APISecret: secret, BaseURL: srv.URL})
	if err != nil {
		t.Fatal(err)
	}
	p, err := c.OutageCache(context.Background(), RadiusOutageCacheRequest{HaveUntil: step, Have: []string{"u1"}})
	if err != nil {
		t.Fatal(err)
	}
	cache, err := c.OpenOutagePage(p)
	if err != nil {
		t.Fatal(err)
	}
	if cache.Policy != "offline_codes" || cache.Members == nil || cache.Next != "" || len(cache.Users) != 1 || cache.KDF.Length != 4 {
		t.Fatalf("opened page: %+v", cache)
	}
	u := cache.Users[0]
	got, ok := MatchOutageCode(u.Salt, u.Digests, u.FromStep, cache.Until, cache.KDF.Iterations, cache.KDF.Length, cache.StepSeconds, "k7p 2qxa", now)
	if !ok || got != step {
		t.Fatalf("match = %d %v, want %d", got, ok, step)
	}
	if _, ok := MatchOutageCode(u.Salt, u.Digests, u.FromStep, cache.Until, cache.KDF.Iterations, cache.KDF.Length, cache.StepSeconds, "K7P2QXA", now.Add(5*time.Minute)); ok {
		t.Fatal("a code after until matched")
	}
	// Changed on the way or on disk: refused.
	tampered := *p
	tampered.Payload = base64.StdEncoding.EncodeToString([]byte(`{"policy":"password_only"}`))
	if _, err := c.OpenOutagePage(&tampered); err != ErrOutagePageSignature {
		t.Fatalf("tampered page: %v", err)
	}
	if _, err := OpenOutagePage("another-secret", p); err != ErrOutagePageSignature {
		t.Fatalf("other secret: %v", err)
	}

	res, err := c.OutageLog(context.Background(), []RadiusOutageEvent{{ID: "0123456789abcdef", At: now, Username: "jane", UserID: "u1", Outcome: "accepted", Factor: "outage_code", Step: step}})
	if err != nil || res.Written != 1 || len(logged) != 1 {
		t.Fatalf("outage log: %+v %v %v", res, err, logged)
	}
}
