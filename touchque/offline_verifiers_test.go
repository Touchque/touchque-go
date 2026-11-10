package touchque

import (
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
	v, err := c.Offline.TotpVerifiers(OfflineTotpVerifiersOptions{ExternalUsernames: []string{"vpn@example.com", "nobody@example.com"}, FromStep: step - 1, Steps: 4})
	if err != nil {
		t.Fatal(err)
	}
	if len(v.Users) != 1 || v.Users[0].ExternalUsername != "vpn@example.com" || len(v.Users[0].Digests) != 44 || v.NotAfterStep != step+2 {
		t.Fatalf("unexpected verifiers: %+v", v)
	}
	// The fake's code is K7P2QXA at every step.
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

	fake.opts(map[string]interface{}{"outageVerifiersDisabled": true})
	if _, err := c.Offline.TotpVerifiers(OfflineTotpVerifiersOptions{ExternalUsernames: []string{"vpn@example.com"}}); err == nil {
		t.Fatal("expected an error when the workspace policy is off")
	}
}
