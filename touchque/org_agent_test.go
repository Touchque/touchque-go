package touchque

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"
)

// An organization's AI agent on Touchque SSO against the shared fake API's
// /sso/token: its own key or its platform's token, a DPoP proof, and calls to
// an app that checks the proof against the token's key.

const orgAgentApp = "tqapp_paymentsapi0000000000"

func fakePost(t *testing.T, base, path string, body interface{}) map[string]interface{} {
	t.Helper()
	b, _ := json.Marshal(body)
	resp, err := http.Post(base+path, "application/json", bytes.NewReader(b))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	out := map[string]interface{}{}
	_ = json.NewDecoder(resp.Body).Decode(&out)
	return out
}

func callResource(t *testing.T, agent *OrgAgent, base, scope string) (int, map[string]interface{}, *http.Request) {
	t.Helper()
	req, _ := http.NewRequest("GET", base+"/__test/resource", nil)
	if err := agent.Authorize(req, "", scope); err != nil {
		t.Fatal(err)
	}
	return sendResource(t, req)
}

func sendResource(t *testing.T, req *http.Request) (int, map[string]interface{}, *http.Request) {
	t.Helper()
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	out := map[string]interface{}{}
	_ = json.NewDecoder(resp.Body).Decode(&out)
	return resp.StatusCode, out, req
}

func TestOrgAgentOwnKey(t *testing.T) {
	api := startFakeAPI(t)
	keys, _ := GenerateAgentKey("ES256")
	id := "oagt_abcdefghijkmnpqrstuv"
	fakePost(t, api.baseURL, "/__test/org-agent", map[string]interface{}{"agentId": id, "publicKey": keys.PublicJWK, "audiences": []string{orgAgentApp}, "scopes": []string{"invoices:read", "payments:create"}})
	agent, err := NewOrgAgent(OrgAgentConfig{AgentID: id, PrivateKey: keys.PrivateJWK, Issuer: api.baseURL})
	if err != nil {
		t.Fatal(err)
	}
	token, err := agent.GetToken("", "invoices:read")
	if err != nil || token.TokenType != "DPoP" || token.ExpiresIn != 300 || token.Scope != "invoices:read" {
		t.Fatalf("token: %+v %v", token, err)
	}
	if again, _ := agent.GetToken("", "invoices:read"); again != token {
		t.Fatal("the token was not reused")
	}
	status, body, req := callResource(t, agent, api.baseURL, "invoices:read")
	if status != 200 || body["sub"] != id || body["aud"] != orgAgentApp || body["via"] != "key" {
		t.Fatalf("resource: %d %+v", status, body)
	}
	// A proof is for one request: sent again, the app refuses it.
	replay, _ := http.NewRequest("GET", req.URL.String(), nil)
	replay.Header = req.Header.Clone()
	if status, _, _ := sendResource(t, replay); status != 401 {
		t.Fatalf("replayed proof: %d", status)
	}
	var apiErr *APIError
	if _, err := agent.GetToken("", "payments:refund"); !errors.As(err, &apiErr) || apiErr.Code != "invalid_scope" {
		t.Fatalf("scope: %v", err)
	}
}

func TestOrgAgentPlatformToken(t *testing.T) {
	api := startFakeAPI(t)
	id := "oagt_bbbbbbbbbbbbbbbbbbbb"
	fakePost(t, api.baseURL, "/__test/org-agent", map[string]interface{}{"agentId": id, "workload": map[string]string{"subject": "repo:acme/payments:ref:refs/heads/main", "audience": "touchque"}, "audiences": []string{orgAgentApp}, "scopes": []string{"invoices:read"}})
	platform := func(sub string) func() (string, error) {
		return func() (string, error) {
			return fakePost(t, api.baseURL, "/__test/workload-token", map[string]string{"sub": sub, "aud": "touchque"})["token"].(string), nil
		}
	}
	agent, _ := NewOrgAgent(OrgAgentConfig{AgentID: id, Issuer: api.baseURL, Assertion: platform("repo:acme/payments:ref:refs/heads/main")})
	if status, body, _ := callResource(t, agent, api.baseURL, ""); status != 200 || body["via"] != "workload" {
		t.Fatalf("resource: %d %+v", status, body)
	}
	wrong, _ := NewOrgAgent(OrgAgentConfig{AgentID: id, Issuer: api.baseURL, Assertion: platform("repo:evil/x")})
	if _, err := wrong.GetToken("", ""); err == nil {
		t.Fatal("a token that does not fit the policy was accepted")
	}
}

func TestOrgAgentConfiguration(t *testing.T) {
	if _, err := NewOrgAgent(OrgAgentConfig{AgentID: "agt_abcdefghijkmnpqrstuv", Assertion: func() (string, error) { return "x", nil }}); err == nil {
		t.Fatal("a partner agent id was accepted")
	}
	if _, err := NewOrgAgent(OrgAgentConfig{AgentID: "oagt_abcdefghijkmnpqrstuv", Issuer: "http://sso.example.com", Assertion: func() (string, error) { return "x", nil }}); err == nil {
		t.Fatal("a plaintext issuer was accepted")
	}
}

func TestOrgAgentForAMember(t *testing.T) {
	api := startFakeAPI(t)
	keys, _ := GenerateAgentKey("ES256")
	id := "oagt_cccccccccccccccccccc"
	fakePost(t, api.baseURL, "/__test/org-agent", map[string]interface{}{"agentId": id, "publicKey": keys.PublicJWK, "audiences": []string{orgAgentApp}, "scopes": []string{"payments:create"}, "delegation": []string{"token_exchange", "ciba"}})
	agent, err := NewOrgAgent(OrgAgentConfig{AgentID: id, PrivateKey: keys.PrivateJWK, Issuer: api.baseURL})
	if err != nil {
		t.Fatal(err)
	}
	call := func(token string) map[string]interface{} {
		req, _ := http.NewRequest("GET", api.baseURL+"/__test/resource", nil)
		proof, _ := agent.DPoPProof("GET", req.URL.String(), token)
		req.Header.Set("Authorization", "DPoP "+token)
		req.Header.Set("DPoP", proof)
		_, body, _ := sendResource(t, req)
		return body
	}
	exchanged, err := agent.ExchangeToken("member:ada@acme.com", "", "")
	if err != nil || call(exchanged.AccessToken)["sub"] != "ada@acme.com" {
		t.Fatalf("exchange: %+v %v", exchanged, err)
	}
	google, err := agent.GetConnectionToken("member:ada@acme.com", "google", "email")
	if err != nil || google.AccessToken != "ya29.ada@acme.com" || google.TokenType != "Bearer" || google.Scope != "email" || google.Connection != "google" || google.ExpiresIn != 3599 {
		t.Fatalf("vault: %+v %v", google, err)
	}
	var vaultErr *APIError
	if _, err := agent.GetConnectionToken("member:ada@acme.com", "github", ""); !errors.As(err, &vaultErr) || vaultErr.Code != "invalid_grant" {
		t.Fatalf("vault refusal: %v", err)
	}
	payment := map[string]interface{}{"type": "payment_initiation", "instructedAmount": map[string]interface{}{"currency": "TRY", "amount": "500.00"}}
	ask, err := agent.AskMember(AskMemberParams{LoginHint: "ada@acme.com", BindingMessage: "Pay invoice 42", AuthorizationDetails: []map[string]interface{}{payment}})
	if err != nil || ask.BindingCode != "42" || ask.Interval != 1 {
		t.Fatalf("ask: %+v %v", ask, err)
	}
	go func() {
		time.Sleep(1500 * time.Millisecond)
		fakePost(t, api.baseURL, "/__test/ciba-answer", map[string]interface{}{"authReqId": ask.AuthReqID, "approve": true})
	}()
	approved, err := agent.WaitForMember(context.Background(), ask)
	if err != nil || len(approved.AuthorizationDetails) != 1 || call(approved.AccessToken)["act"] != id {
		t.Fatalf("approved: %+v %v", approved, err)
	}
	// A shared account: the member's extension opens it; the agent learns only how it ended.
	fakePost(t, api.baseURL, "/__test/org-agent", map[string]interface{}{"agentId": id, "publicKey": keys.PublicJWK, "audiences": []string{orgAgentApp}, "scopes": []string{"payments:create"}, "delegation": []string{"token_exchange", "ciba"}, "sharedAccounts": []string{"k3JInstagramAcme01"}})
	shared, err := agent.AskToOpenSharedAccount("k3JInstagramAcme01", "ada@acme.com", "Post the launch photo")
	if err != nil || shared.Status != "waiting_member" || !strings.Contains(shared.OpenURL, "/agent-ask?ask="+shared.AskID) {
		t.Fatalf("shared ask: %+v %v", shared, err)
	}
	fakePost(t, api.baseURL, "/__test/shared-ask-answer", map[string]interface{}{"askId": shared.AskID, "status": "refused", "reason": "declined_on_phone"})
	if s, err := agent.WaitForSharedAccount(context.Background(), shared); err != nil || s.Status != "refused" || s.Reason != "declined_on_phone" {
		t.Fatalf("shared result: %+v %v", s, err)
	}
	no, _ := agent.AskMember(AskMemberParams{LoginHint: "ada@acme.com"})
	fakePost(t, api.baseURL, "/__test/ciba-answer", map[string]interface{}{"authReqId": no.AuthReqID, "approve": false})
	var apiErr *APIError
	if _, err := agent.WaitForMember(context.Background(), no); !errors.As(err, &apiErr) || apiErr.Code != "access_denied" {
		t.Fatalf("denied: %v", err)
	}
}
