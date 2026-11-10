package touchque

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"testing"
)

// Shared Signals SETs: the cross-SDK vectors (fixtures/security-event-vectors.json).
func TestSecurityEventVectors(t *testing.T) {
	raw, err := os.ReadFile("../fixtures/security-event-vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var V struct {
		Issuer   string                 `json:"issuer"`
		Audience string                 `json:"audience"`
		JWKS     map[string]interface{} `json:"jwks"`
		Valid    []struct {
			Name   string `json:"name"`
			Token  string `json:"token"`
			Expect struct {
				JTI      string                 `json:"jti"`
				Issuer   string                 `json:"issuer"`
				Audience []string               `json:"audience"`
				IssuedAt int64                  `json:"issuedAt"`
				TXN      *string                `json:"txn"`
				Subject  map[string]interface{} `json:"subject"`
				Type     string                 `json:"type"`
				Name     *string                `json:"name"`
				Claims   map[string]interface{} `json:"claims"`
			} `json:"expect"`
		} `json:"valid"`
		Invalid []struct {
			Name  string `json:"name"`
			Token string `json:"token"`
			Error string `json:"error"`
		} `json:"invalid"`
	}
	if err := json.Unmarshal(raw, &V); err != nil {
		t.Fatal(err)
	}
	v, err := NewSecurityEventVerifier(SecurityEventVerifierConfig{Issuer: V.Issuer, Audience: V.Audience, JWKS: V.JWKS})
	if err != nil {
		t.Fatal(err)
	}
	str := func(p *string) string {
		if p == nil {
			return ""
		}
		return *p
	}
	for _, c := range V.Valid {
		e, err := v.Verify(context.Background(), c.Token)
		if err != nil {
			t.Fatalf("%s: %v", c.Name, err)
		}
		x := c.Expect
		got := []interface{}{e.JTI, e.Issuer, e.Audience, e.IssuedAt, e.TXN, e.Subject, e.Type, e.Name, e.Claims}
		want := []interface{}{x.JTI, x.Issuer, x.Audience, x.IssuedAt, str(x.TXN), x.Subject, x.Type, str(x.Name), x.Claims}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("%s: got %v, want %v", c.Name, got, want)
		}
	}
	for _, c := range V.Invalid {
		_, err := v.Verify(context.Background(), c.Token)
		var se *SecurityEventError
		if !errors.As(err, &se) || se.Code != c.Error {
			t.Errorf("%s: got %v, want %s", c.Name, err, c.Error)
		}
	}
	if SecurityEventTypes["session-revoked"] != "https://schemas.openid.net/secevent/caep/event-type/session-revoked" {
		t.Error("short name")
	}
}

// Keys from the transmitter's /.well-known/ssf-configuration, and a poll
// (RFC 8936), against a local stub: the Node SDK's cases.
func TestSecurityEventDiscoveryAndPoll(t *testing.T) {
	raw, err := os.ReadFile("../fixtures/security-event-vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var V struct {
		Audience string                 `json:"audience"`
		JWKS     map[string]interface{} `json:"jwks"`
		Valid    []struct {
			Token  string `json:"token"`
			Expect struct {
				JTI string `json:"jti"`
			} `json:"expect"`
		} `json:"valid"`
	}
	if err := json.Unmarshal(raw, &V); err != nil {
		t.Fatal(err)
	}
	first := V.Valid[0]

	var polled struct {
		Auth string
		Body map[string]interface{}
	}
	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/.well-known/ssf-configuration":
			_ = json.NewEncoder(w).Encode(map[string]string{"issuer": server.URL, "jwks_uri": server.URL + "/jwks"})
		case "/jwks":
			_ = json.NewEncoder(w).Encode(V.JWKS)
		default:
			polled.Auth = r.Header.Get("Authorization")
			_ = json.NewDecoder(r.Body).Decode(&polled.Body)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"sets": map[string]string{first.Expect.JTI: first.Token}, "moreAvailable": false})
		}
	}))
	defer server.Close()

	// The vectors' issuer is not this one: the signature verifies with the
	// discovered keys, the issuer does not.
	v, err := NewSecurityEventVerifier(SecurityEventVerifierConfig{Issuer: server.URL, Audience: V.Audience})
	if err != nil {
		t.Fatal(err)
	}
	var se *SecurityEventError
	if _, err := v.Verify(context.Background(), first.Token); !errors.As(err, &se) || se.Code != "invalid_issuer" {
		t.Fatalf("got %v, want invalid_issuer", err)
	}

	max := 5
	out, err := PollSecurityEvents(context.Background(), PollSecurityEventsParams{URL: server.URL + "/ssf/poll/s1", Token: "tqssf_x", Ack: []string{"a"}, MaxEvents: &max})
	if err != nil || out.Sets[first.Expect.JTI] != first.Token || out.MoreAvailable {
		t.Fatalf("poll = %+v, %v", out, err)
	}
	want := map[string]interface{}{"ack": []interface{}{"a"}, "maxEvents": float64(5)}
	if polled.Auth != "Bearer tqssf_x" || !reflect.DeepEqual(polled.Body, want) {
		t.Fatalf("polled = %+v", polled)
	}
}

// A metadata document for another issuer is not trusted, and a poll the
// transmitter refuses comes back as its RFC 8936 error.
func TestSecurityEventDiscoveryMismatchAndPollError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/.well-known/ssf-configuration" {
			_ = json.NewEncoder(w).Encode(map[string]string{"issuer": "https://elsewhere.example", "jwks_uri": "https://elsewhere.example/jwks"})
			return
		}
		w.WriteHeader(http.StatusUnauthorized)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "authentication_failed"})
	}))
	defer server.Close()

	v, err := NewSecurityEventVerifier(SecurityEventVerifierConfig{Issuer: server.URL, Audience: "https://receiver.example.com"})
	if err != nil {
		t.Fatal(err)
	}
	token := "eyJhbGciOiJSUzI1NiIsImtpZCI6ImsxIiwidHlwIjoic2VjZXZlbnQrand0In0.e30.c2ln"
	var se *SecurityEventError
	if _, err := v.Verify(context.Background(), token); !errors.As(err, &se) || se.Code != "temporarily_unavailable" {
		t.Fatalf("got %v, want temporarily_unavailable", err)
	}
	if _, err := PollSecurityEvents(context.Background(), PollSecurityEventsParams{URL: server.URL + "/ssf/poll/s1", Token: "wrong"}); !errors.As(err, &se) || se.Code != "authentication_failed" {
		t.Fatalf("got %v, want authentication_failed", err)
	}
	if _, err := PollSecurityEvents(context.Background(), PollSecurityEventsParams{URL: "http://sso.example/ssf/poll/s1", Token: "tqssf_x"}); err == nil {
		t.Fatal("a plaintext poll URL off this machine must be refused")
	}
}
