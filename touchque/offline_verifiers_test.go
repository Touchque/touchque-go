package touchque

import (
	"encoding/base64"
	"testing"
	"time"
)

func TestOffline_TotpVerifiersAgainstTheFakeAPIThenMatchOffline(t *testing.T) {
	fake := startFakeAPI(t)
	defer fake.close()
	c := fake.client(t)
	fake.link("vpn@example.com")
	now := time.Now()
	step := now.Unix() / 30
	v, err := c.Offline.TotpVerifiers(OfflineTotpVerifiersOptions{ExternalUsernames: []string{"vpn@example.com", "nobody@example.com"}, Scope: OfflineOutageScope{ID: "acme", Name: "Acme"}, FromStep: step - 1, Steps: 4})
	if err != nil {
		t.Fatal(err)
	}
	if len(v.Users) != 1 || v.Users[0].ExternalUsername != "vpn@example.com" || len(v.Users[0].Digests) != 32 || v.DigestsPerStep != 1 || v.Scope == nil || v.Scope.ID != "acme" || v.NotAfterStep != step+2 {
		t.Fatalf("unexpected verifiers: %+v", v)
	}
	// The fake's outage code is K7P2QXA at every step (one digest a step).
	got, ok := MatchTotpVerifier(v, &v.Users[0], "k7p-2qxa", now)
	if !ok || got != step {
		t.Fatalf("match = %d %v, want %d", got, ok, step)
	}
	if _, ok := MatchTotpVerifier(v, &v.Users[0], "K7P2QXB", now); ok {
		t.Fatal("a wrong code matched")
	}
	if _, ok := MatchTotpVerifier(v, &v.Users[0], "K7P2QXA", now.Add(time.Hour)); ok {
		t.Fatal("a code past notAfterStep matched")
	}
	if _, ok := MatchTotpVerifier(v, &v.Users[0], "K7P2QX1", now); ok {
		t.Fatal("a code outside the alphabet matched")
	}

	// A missing scope is refused like the API does.
	if _, err := c.Offline.TotpVerifiers(OfflineTotpVerifiersOptions{ExternalUsernames: []string{"vpn@example.com"}}); err == nil {
		t.Fatal("expected scope_required without a scope")
	}

	// An answer without digestsPerStep has two digests a step.
	two := &OfflineTotpVerifiers{StepSeconds: 30, FromStep: v.FromStep, Steps: v.Steps, NotAfterStep: v.NotAfterStep}
	two.KDF.Iterations, two.KDF.Length = 10, 6
	u := v.Users[0]
	raw, _ := base64.StdEncoding.DecodeString(u.Digests)
	var doubled []byte
	for i := 0; i < len(raw); i += 6 {
		doubled = append(doubled, raw[i:i+6]...)
		doubled = append(doubled, raw[i:i+6]...)
	}
	u.Digests = base64.StdEncoding.EncodeToString(doubled)
	if got, ok := MatchTotpVerifier(two, &u, "K7P2QXA", now); !ok || got != step {
		t.Fatalf("two-per-step match = %d %v", got, ok)
	}

	fake.opts(map[string]interface{}{"outageVerifiersDisabled": true})
	if _, err := c.Offline.TotpVerifiers(OfflineTotpVerifiersOptions{ExternalUsernames: []string{"vpn@example.com"}, Scope: OfflineOutageScope{ID: "acme", Name: "Acme"}}); err == nil {
		t.Fatal("expected an error when the workspace policy is off")
	}
}
