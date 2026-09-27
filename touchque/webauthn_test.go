package touchque

import (
	"encoding/json"
	"net/http"
	"testing"
)

func TestWebAuthn_RegisterOptions_DiscoverableOnlyWhenTrue(t *testing.T) {
	var seen []bool
	client, closeFn := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/webauthn/register/options" {
			t.Errorf("path: %s", r.URL.Path)
		}
		var body map[string]interface{}
		_ = json.NewDecoder(r.Body).Decode(&body)
		_, hasDisc := body["discoverable"]
		seen = append(seen, hasDisc)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"challenge": "c"})
	})
	defer closeFn()

	if _, err := client.WebAuthn.RegisterOptions("a@b.com", false); err != nil {
		t.Fatal(err)
	}
	if _, err := client.WebAuthn.RegisterOptions("a@b.com", true); err != nil {
		t.Fatal(err)
	}
	if len(seen) != 2 || seen[0] != false || seen[1] != true {
		t.Fatalf("discoverable flag not passed correctly: %v", seen)
	}
}

func TestWebAuthn_RegisterVerify(t *testing.T) {
	client, closeFn := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/webauthn/register/verify" {
			t.Errorf("path: %s", r.URL.Path)
		}
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"verified": true, "credentialId": "cred_1"})
	})
	defer closeFn()

	resp, err := client.WebAuthn.RegisterVerify("a@b.com", map[string]interface{}{"id": "x"}, "MacBook")
	if err != nil {
		t.Fatal(err)
	}
	if !resp.Verified || resp.CredentialID != "cred_1" {
		t.Fatalf("unexpected: %+v", resp)
	}
}

func TestWebAuthn_AuthenticateOptionsAndVerify(t *testing.T) {
	client, closeFn := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/webauthn/login/options":
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"challenge": "c"})
		case "/webauthn/login/verify":
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"success": true, "message": "ok"})
		default:
			t.Errorf("unexpected path %s", r.URL.Path)
		}
	})
	defer closeFn()

	if _, err := client.WebAuthn.AuthenticateOptions("req_1"); err != nil {
		t.Fatal(err)
	}
	resp, err := client.WebAuthn.AuthenticateVerify("req_1", map[string]interface{}{"id": "a"})
	if err != nil {
		t.Fatal(err)
	}
	if !resp.Success {
		t.Fatalf("unexpected: %+v", resp)
	}
}

func TestWebAuthn_PrimaryOptionsAndVerify(t *testing.T) {
	client, closeFn := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/webauthn/authenticate/primary/options":
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"attemptId": "att_1", "options": map[string]interface{}{"challenge": "c"}})
		case "/webauthn/authenticate/primary/verify":
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"success": false, "requiresStepUp": true, "externalUsername": "a@b.com", "riskScore": float64(0.95),
			})
		default:
			t.Errorf("unexpected path %s", r.URL.Path)
		}
	})
	defer closeFn()

	opts, err := client.WebAuthn.PrimaryOptions("a@b.com")
	if err != nil || opts.AttemptID != "att_1" {
		t.Fatalf("primaryOptions: %+v %v", opts, err)
	}
	v, err := client.WebAuthn.PrimaryVerify("att_1", map[string]interface{}{"id": "a"})
	if err != nil || !v.RequiresStepUp || v.RiskScore != 0.95 {
		t.Fatalf("primaryVerify: %+v %v", v, err)
	}
}

func TestWebAuthn_ListCredentials_QueryParam(t *testing.T) {
	client, closeFn := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/webauthn/credentials" || r.URL.Query().Get("externalUsername") != "a@b.com" {
			t.Errorf("path/query: %s ?%s", r.URL.Path, r.URL.RawQuery)
		}
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"credentials": []interface{}{map[string]interface{}{"id": "c1", "credentialId": "k1", "backedUp": true}},
		})
	})
	defer closeFn()

	creds, err := client.WebAuthn.ListCredentials("a@b.com")
	if err != nil {
		t.Fatal(err)
	}
	if len(creds) != 1 || creds[0].ID != "c1" || !creds[0].BackedUp {
		t.Fatalf("unexpected: %+v", creds)
	}
}

func TestWebAuthn_DeleteCredential(t *testing.T) {
	client, closeFn := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "DELETE" || r.URL.EscapedPath() != "/webauthn/credentials/cred%2F1" {
			t.Errorf("method/path: %s %s", r.Method, r.URL.EscapedPath())
		}
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"deleted": true})
	})
	defer closeFn()

	resp, err := client.WebAuthn.DeleteCredential("cred/1")
	if err != nil {
		t.Fatal(err)
	}
	if !resp.Deleted {
		t.Fatalf("unexpected: %+v", resp)
	}
}
