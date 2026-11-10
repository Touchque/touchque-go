package touchque

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
)

func TestMyAccount(t *testing.T) {
	var form url.Values
	var auth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.URL.Path == "/oauth/token":
			raw, _ := io.ReadAll(r.Body)
			form, _ = url.ParseQuery(string(raw))
			_, _ = w.Write([]byte(`{"access_token":"me-at","token_type":"Bearer","expires_in":600,"scope":"read:me update:me","refresh_token":"tqr_2"}`))
		case r.URL.Path == "/me/v1/profile" && r.Method == http.MethodPatch:
			auth = r.Header.Get("Authorization")
			var in map[string]interface{}
			_ = json.NewDecoder(r.Body).Decode(&in)
			in["id"] = "usr_1"
			_ = json.NewEncoder(w).Encode(in)
		case r.URL.EscapedPath() == "/me/v1/sessions/s%201":
			w.WriteHeader(http.StatusNoContent)
		case r.URL.Path == "/me/v1" && r.Method == http.MethodDelete:
			w.Header().Set("WWW-Authenticate", `Bearer error="insufficient_user_authentication", max_age="600"`)
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"error":"insufficient_user_authentication","error_description":"A more recent sign-in is required"}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()
	ctx := context.Background()
	login, _ := NewHostedLogin(HostedLoginConfig{Domain: srv.URL, ClientID: "c1"})

	me, err := login.MyAccountToken(ctx, "tqr_1", "")
	if err != nil || me.AccessToken != "me-at" || me.RefreshToken != "tqr_2" {
		t.Fatalf("token %+v %v", me, err)
	}
	if form.Get("audience") != srv.URL+"/me/" || form.Get("scope") != "read:me update:me" {
		t.Fatalf("form %v", form)
	}
	account := login.MyAccount(me.AccessToken)
	out, err := account.UpdateProfile(ctx, map[string]interface{}{"name": "Zoë"})
	if err != nil || out["name"] != "Zoë" || auth != "Bearer me-at" {
		t.Fatalf("profile %v %v %q", out, err, auth)
	}
	if err := account.EndSession(ctx, "s 1"); err != nil {
		t.Fatalf("end session %v", err)
	}
	if login.AccountURL("security") != srv.URL+"/account/security" {
		t.Fatal(login.AccountURL("security"))
	}

	_, err = account.DeleteAccount(ctx)
	var e *MyAccountError
	if !errors.As(err, &e) || !e.StepUp() || e.MaxAge != 600 || e.Status != 401 {
		t.Fatalf("step-up %#v", err)
	}
}
