package touchque

// AI agents in the Go SDK: management calls send what the shared vectors
// (fixtures/agent-vectors.json) say, and Agent signs in with its own key
// against the shared fake API, which checks the private_key_jwt assertion and
// the DPoP proofs like the real API.

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

type agentVectors struct {
	Thumbprints []struct {
		JWK        map[string]interface{} `json:"jwk"`
		Thumbprint string                 `json:"thumbprint"`
	} `json:"thumbprints"`
	Ath []struct {
		AccessToken string `json:"accessToken"`
		Ath         string `json:"ath"`
	} `json:"ath"`
	Calls         []map[string]interface{} `json:"calls"`
	ApprovalToken struct {
		JWKS       JWKS                   `json:"jwks"`
		Token      string                 `json:"token"`
		VerifyAt   int64                  `json:"verifyAt"`
		Claims     map[string]interface{} `json:"claims"`
		Tampered   string                 `json:"tampered"`
		WrongType  string                 `json:"wrongType"`
		Audience   string                 `json:"audience"`
		NoAudience struct {
			Token string `json:"token"`
			JWKS  JWKS   `json:"jwks"`
		} `json:"noAudience"`
	} `json:"approvalToken"`
	Matching []struct {
		Name    string      `json:"name"`
		Expect  interface{} `json:"expect"`
		Matches bool        `json:"matches"`
	} `json:"matching"`
}

func loadAgentVectors(t *testing.T) agentVectors {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "fixtures", "agent-vectors.json"))
	if err != nil {
		t.Fatal(err)
	}
	var v agentVectors
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	return v
}

func TestAgentKeyVectors(t *testing.T) {
	v := loadAgentVectors(t)
	for _, c := range v.Thumbprints {
		if got := JWKThumbprint(c.JWK); got != c.Thumbprint {
			t.Errorf("thumbprint %v = %s, want %s", c.JWK["crv"], got, c.Thumbprint)
		}
	}
	for _, c := range v.Ath {
		sum := sha256.Sum256([]byte(c.AccessToken))
		if b64url(sum[:]) != c.Ath {
			t.Errorf("ath = %s, want %s", b64url(sum[:]), c.Ath)
		}
	}
	ec, err := GenerateAgentKey("")
	if err != nil || ec.PublicJWK["alg"] != "ES256" || ec.PublicJWK["kid"] != JWKThumbprint(ec.PublicJWK) {
		t.Fatalf("ES256 key: %v %v", ec, err)
	}
	if _, private := ec.PublicJWK["d"]; private {
		t.Fatal("the public JWK has private parts")
	}
	ed, err := GenerateAgentKey("EdDSA")
	if err != nil || ed.PublicJWK["crv"] != "Ed25519" {
		t.Fatalf("EdDSA key: %v %v", ed, err)
	}
}

func TestAgentManagementVectors(t *testing.T) {
	api := startFakeAPI(t)
	c := api.client(t)
	v := loadAgentVectors(t)
	k1, _ := GenerateAgentKey("ES256")
	k2, _ := GenerateAgentKey("EdDSA")
	id := ""
	for _, call := range v.Calls {
		name := call["name"].(string)
		a := call["args"].(map[string]interface{})
		var err error
		switch name {
		case "create":
			var agent *AgentInfo
			agent, err = c.Agents.Create(CreateAgentParams{Name: a["name"].(string), AllowedTypes: []string{"SEND_MONEY"}, PublicKey: k1.PublicJWK,
				OwnerEmail: a["ownerEmail"].(string), Platform: a["platform"].(string), ReviewInDays: int(a["reviewInDays"].(float64))})
			if agent != nil {
				id = agent.ID
			}
		case "list":
			_, _, err = c.Agents.List(a["status"].(string))
		case "get":
			_, err = c.Agents.Get(id)
		case "update":
			desc := a["description"].(string)
			_, err = c.Agents.Update(id, UpdateAgentParams{ReviewInDays: int(a["reviewInDays"].(float64)), Description: &desc})
		case "addKey":
			_, err = c.Agents.AddKey(id, k2.PublicJWK)
		case "removeKey":
			_, err = c.Agents.RemoveKey(id, k2.PublicJWK["kid"].(string))
		case "suspend":
			_, err = c.Agents.Suspend(id, a["reason"].(string))
		case "resume":
			_, err = c.Agents.Resume(id)
		case "setPolicy":
			p := a["policy"].(map[string]interface{})
			_, err = c.Agents.SetPolicy(id, AgentPolicy{RequestsPerUserPer10Min: int(p["requestsPerUserPer10Min"].(float64)), AmountPerRequest: map[string]string{"TRY": "1000.00"}, Background: "never", NewRecipients: "deny"})
		case "listEvents":
			_, err = c.Agents.ListEvents(AgentEventOptions{After: a["after"].(string), Limit: int(a["limit"].(float64))})
		case "getWorkspacePolicy":
			_, err = c.Agents.GetWorkspacePolicy()
		case "setWorkspacePolicy":
			_, err = c.Agents.SetWorkspacePolicy(AgentPolicy{AmountPerRequest: map[string]string{"TRY": "5000.00"}, RequirePasskeyAbove: map[string]string{"TRY": "1000.00"}})
		case "listBlocks":
			_, err = c.Agents.ListBlocks(id)
		case "killSwitch":
			_, err = c.Agents.SetKillSwitch(true, a["reason"].(string))
		case "killSwitchOff":
			_, err = c.Agents.SetKillSwitch(false, "")
		case "revoke":
			_, err = c.Agents.Revoke(id)
		}
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		calls := api.calls()
		last := calls[len(calls)-1]
		k1j, _ := json.Marshal(k1.PublicJWK)
		k2j, _ := json.Marshal(k2.PublicJWK)
		wantRaw, _ := json.Marshal(call)
		text := strings.NewReplacer(`"{publicKey}"`, string(k1j), `"{publicKey2}"`, string(k2j), "{id}", id, "{kid}", url.PathEscape(k2.PublicJWK["kid"].(string))).Replace(string(wantRaw))
		var want map[string]interface{}
		_ = json.Unmarshal([]byte(text), &want)
		if last["method"] != want["method"] || last["path"] != want["path"] {
			t.Fatalf("%s: %v %v, want %v %v", name, last["method"], last["path"], want["method"], want["path"])
		}
		if q, ok := want["query"].(string); ok && last["url"] != want["path"].(string)+"?"+q {
			t.Fatalf("%s: url %v", name, last["url"])
		}
		if body, ok := want["body"]; ok && !reflect.DeepEqual(last["body"], body) {
			t.Fatalf("%s: body %v, want %v", name, last["body"], body)
		}
	}
	if _, err := c.Agents.Create(CreateAgentParams{Name: "x", AllowedTypes: []string{"LOGIN"}, PublicKey: k1.PrivateJWK}); err == nil {
		t.Fatal("a private key must be refused")
	}
}

func TestAgentSignsInWithItsOwnKey(t *testing.T) {
	api := startFakeAPI(t)
	c := api.client(t)
	for _, alg := range []string{"ES256", "EdDSA"} {
		keys, _ := GenerateAgentKey(alg)
		created, err := c.Agents.Create(CreateAgentParams{Name: "agent " + alg, AllowedTypes: []string{"LOGIN"}, PublicKey: keys.PublicJWK})
		if err != nil {
			t.Fatal(err)
		}
		asJSON, _ := json.Marshal(keys.PrivateJWK)
		for _, key := range []interface{}{keys.PrivateJWK, string(asJSON)} {
			agent, err := NewAgent(AgentConfig{AgentID: created.ID, PrivateKey: key, BaseURL: api.baseURL})
			if err != nil {
				t.Fatal(err)
			}
			me, err := agent.Me()
			if err != nil {
				t.Fatalf("%s: %v", alg, err)
			}
			if me.Agent.ID != created.ID || me.Scope != "agent:read approvals:request approvals:read vault:read" {
				t.Fatalf("me = %+v", me)
			}
		}
	}
}

func TestAgentTokenVault(t *testing.T) {
	api := startFakeAPI(t)
	c := api.client(t)
	keys, _ := GenerateAgentKey("ES256")
	created, _ := c.Agents.Create(CreateAgentParams{Name: "calendar", AllowedTypes: []string{"LOGIN"}, PublicKey: keys.PublicJWK})
	agent, _ := NewAgent(AgentConfig{AgentID: created.ID, PrivateKey: keys.PrivateJWK, BaseURL: api.baseURL})
	conn, err := c.Agents.Vault.PutConnection("google", AgentVaultConnectionParams{Provider: "google", ClientID: "acme.apps.googleusercontent.com", ClientSecret: "g-secret", AgentIDs: []string{created.ID}})
	if err != nil || !conn.HasClientSecret || len(conn.AgentIDs) != 1 {
		t.Fatalf("connection: %+v %v", conn, err)
	}
	if _, err := c.Agents.Vault.Deposit("google", "jane@example.com", AgentVaultDeposit{AccessToken: "ya29.jane", RefreshToken: "1//jane", ExpiresIn: 3599, Scope: "calendar.readonly"}); err != nil {
		t.Fatal(err)
	}
	if list, _ := c.Agents.Vault.ListAccounts("jane@example.com"); len(list) != 1 || !list[0].CanRefresh {
		t.Fatalf("accounts: %+v", list)
	}
	got, err := agent.GetConnectionToken("jane@example.com", "google", "")
	if err != nil || got.AccessToken != "ya29.jane" || got.TokenType != "Bearer" || got.ExpiresIn != 3599 || got.Connection != "google" {
		t.Fatalf("token: %+v %v", got, err)
	}
	var apiErr *APIError
	if _, err := agent.GetConnectionToken("john@example.com", "google", ""); !errors.As(err, &apiErr) || apiErr.Code != "not_connected" {
		t.Fatalf("not connected: %v", err)
	}
	if err := c.Agents.Vault.RemoveAccount("google", "jane@example.com"); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Agents.Vault.RemoveConnection("google"); err != nil {
		t.Fatal(err)
	}
}

func TestAgentTokenReuseAndRefusals(t *testing.T) {
	api := startFakeAPI(t)
	c := api.client(t)
	keys, _ := GenerateAgentKey("ES256")
	created, _ := c.Agents.Create(CreateAgentParams{Name: "refused", AllowedTypes: []string{"LOGIN"}, PublicKey: keys.PublicJWK})
	agent, _ := NewAgent(AgentConfig{AgentID: created.ID, PrivateKey: keys.PrivateJWK, BaseURL: api.baseURL})
	tokenCalls := func() int {
		n := 0
		for _, call := range api.calls() {
			if call["path"] == "/agents/token" {
				n++
			}
		}
		return n
	}
	if _, err := agent.Me(); err != nil {
		t.Fatal(err)
	}
	if _, err := agent.Me(); err != nil {
		t.Fatal(err)
	}
	if n := tokenCalls(); n != 1 {
		t.Fatalf("token requests = %d, want 1", n)
	}
	_, _ = c.Agents.Suspend(created.ID, "looping")
	var apiErr *APIError
	if _, err := agent.Me(); !errors.As(err, &apiErr) || apiErr.StatusCode != 403 || apiErr.Code != "agent_blocked" || apiErr.Reason != "suspended" {
		t.Fatalf("suspended: %v", err)
	}
	fresh, _ := NewAgent(AgentConfig{AgentID: created.ID, PrivateKey: keys.PrivateJWK, BaseURL: api.baseURL})
	if _, err := fresh.Me(); !errors.As(err, &apiErr) || apiErr.Code != "unauthorized_client" || apiErr.Reason != "suspended" {
		t.Fatalf("fresh while suspended: %v", err)
	}
	_, _ = c.Agents.Resume(created.ID)
	stranger, _ := GenerateAgentKey("ES256")
	spoof, _ := NewAgent(AgentConfig{AgentID: created.ID, PrivateKey: stranger.PrivateJWK, Kid: keys.PublicJWK["kid"].(string), BaseURL: api.baseURL})
	if _, err := spoof.Me(); !errors.As(err, &apiErr) || apiErr.StatusCode != 401 || apiErr.Code != "invalid_client" {
		t.Fatalf("stranger's key: %v", err)
	}
	_, _ = c.Agents.SetKillSwitch(true, "incident")
	if _, err := agent.Me(); !errors.As(err, &apiErr) || apiErr.Reason != "workspace_paused" {
		t.Fatalf("paused: %v", err)
	}
	_, _ = c.Agents.SetKillSwitch(false, "")
	if _, err := agent.Me(); err != nil {
		t.Fatal(err)
	}
}

func TestAgentConfigErrors(t *testing.T) {
	keys, _ := GenerateAgentKey("ES256")
	cases := []AgentConfig{
		{AgentID: "nope", PrivateKey: keys.PrivateJWK},
		{AgentID: "agt_abcdefghijkmnpqrstuv", PrivateKey: "not a key"},
		{AgentID: "agt_abcdefghijkmnpqrstuv", PrivateKey: keys.PrivateJWK, BaseURL: "http://api.example.com"},
	}
	for _, cfg := range cases {
		var cfgErr *ConfigError
		if _, err := NewAgent(cfg); !errors.As(err, &cfgErr) {
			t.Fatalf("%+v: %v", cfg, err)
		}
	}
}

func TestApprovalTokenVectors(t *testing.T) {
	v := loadAgentVectors(t).ApprovalToken
	at := time.Unix(v.VerifyAt, 0)
	claims, err := VerifyApprovalTokenWith(v.Token, v.JWKS, v.Audience, ApprovalExpectation{}, at)
	if err != nil || claims["sub"] != v.Claims["sub"] {
		t.Fatalf("valid token: %v %v", claims, err)
	}
	exp := int64(v.Claims["exp"].(float64))
	for _, c := range []struct {
		token, aud string
		at         time.Time
	}{{v.Tampered, v.Audience, at}, {v.WrongType, v.Audience, at}, {v.Token, "touchque:workspace:other", at}, {v.Token, v.Audience, time.Unix(exp+60, 0)}} {
		var mismatch *ApprovalMismatchError
		if _, err := VerifyApprovalTokenWith(c.token, v.JWKS, c.aud, ApprovalExpectation{}, c.at); !errors.As(err, &mismatch) {
			t.Fatalf("expected a refusal, got %v", err)
		}
	}
	// The audience is required, and a token without aud is refused.
	for _, c := range []struct {
		token string
		jwks  JWKS
		aud   string
		want  string
	}{
		{v.Token, v.JWKS, "touchque:workspace:other", "another workspace"},
		{v.Token, v.JWKS, "", "audience is required"},
		{v.NoAudience.Token, v.NoAudience.JWKS, v.Audience, "names no workspace"},
	} {
		var mismatch *ApprovalMismatchError
		if _, err := VerifyApprovalTokenWith(c.token, c.jwks, c.aud, ApprovalExpectation{}, at); !errors.As(err, &mismatch) || !strings.Contains(mismatch.Message, c.want) {
			t.Fatalf("want %q, got %v", c.want, err)
		}
	}
	for _, m := range loadAgentVectors(t).Matching {
		if got := MatchesAuthorizationDetails(v.Claims["authorization_details"], m.Expect); got != m.Matches {
			t.Errorf("%s: %v, want %v", m.Name, got, m.Matches)
		}
	}
}

func TestAgentAskWaitRedeem(t *testing.T) {
	api := startFakeAPI(t)
	c := api.client(t)
	user := "agent-approvals@example.com"
	api.link(user)
	if _, err := c.ActionTypes.Define("PAY_INVOICE", DefineOptions{}); err != nil {
		t.Fatal(err)
	}
	keys, _ := GenerateAgentKey("ES256")
	created, err := c.Agents.Create(CreateAgentParams{Name: "Invoice bot", AllowedTypes: []string{"PAY_INVOICE"}, PublicKey: keys.PublicJWK})
	if err != nil {
		t.Fatal(err)
	}
	agent, _ := NewAgent(AgentConfig{AgentID: created.ID, PrivateKey: keys.PrivateJWK, BaseURL: api.baseURL})
	payment := loadAgentVectors(t).ApprovalToken.Claims["authorization_details"].([]interface{})[0].(map[string]interface{})

	ask, err := agent.RequestApproval(AgentApprovalParams{User: user, Type: "PAY_INVOICE", AuthorizationDetails: []map[string]interface{}{payment}, Reason: "October rent"})
	if err != nil || ask.Status != "pending" || ask.ChallengeCode != "47" {
		t.Fatalf("ask: %+v %v", ask, err)
	}
	api.approve(ask.ApprovalID)
	done, err := agent.WaitForApproval(context.Background(), ask.ApprovalID, 10*time.Second, 500*time.Millisecond)
	if err != nil || done.ApprovalToken == "" {
		t.Fatalf("wait: %+v %v", done, err)
	}
	// RequireApproval: ask and wait in one call, the number shown while the phone waits.
	shown := ""
	required, err := agent.RequireApproval(context.Background(), AgentApprovalParams{User: user, Type: "PAY_INVOICE", AuthorizationDetails: []map[string]interface{}{payment}},
		func(s *AgentApprovalState) { shown = s.ChallengeCode; api.approve(s.ApprovalID) }, 10*time.Second)
	if err != nil || required.ApprovalToken == "" || shown != "47" {
		t.Fatalf("require: %+v %v %q", required, err, shown)
	}
	// The workspace's own audience comes from GET /agents/approval-audience; another one is refused.
	if own, err := c.Agents.ApprovalAudience(); err != nil || own != "touchque:workspace:fake-workspace" {
		t.Fatalf("audience: %q %v", own, err)
	}
	claims, err := c.Agents.VerifyApprovalToken(done.ApprovalToken, "", ApprovalExpectation{User: user, AuthorizationDetails: payment})
	if err != nil || claims["act"].(map[string]interface{})["sub"] != created.ID {
		t.Fatalf("verify: %v %v", claims, err)
	}
	var mismatch *ApprovalMismatchError
	if _, err := c.Agents.VerifyApprovalToken(done.ApprovalToken, "touchque:workspace:other", ApprovalExpectation{}); !errors.As(err, &mismatch) {
		t.Fatalf("another workspace: %v", err)
	}
	wrong := map[string]interface{}{"instructedAmount": map[string]interface{}{"currency": "TRY", "amount": "5000.00"}}
	if _, err := c.Agents.RedeemApproval(done.ApprovalToken, ApprovalExpectation{AuthorizationDetails: wrong}); !errors.As(err, &mismatch) {
		t.Fatalf("mismatch: %v", err)
	}
	right := map[string]interface{}{"type": "payment_initiation", "instructedAmount": map[string]interface{}{"currency": "try", "amount": "500"}}
	approval, err := c.Agents.RedeemApproval(done.ApprovalToken, ApprovalExpectation{User: user, Type: "PAY_INVOICE", AuthorizationDetails: right})
	if err != nil || approval.ID != ask.ApprovalID || approval.Agent.ID != created.ID {
		t.Fatalf("redeem: %+v %v", approval, err)
	}
	var apiErr *APIError
	if _, err := c.Agents.RedeemApproval(done.ApprovalToken, ApprovalExpectation{}); !errors.As(err, &apiErr) || apiErr.Code != "already_redeemed" {
		t.Fatalf("second redeem: %v", err)
	}

	ask2, _ := agent.RequestApproval(AgentApprovalParams{User: user, Type: "PAY_INVOICE", AuthorizationDetails: []map[string]interface{}{payment}, Presence: "background"})
	if ask2.ChallengeCode != "" {
		t.Fatal("a background request has no number")
	}
	api.reject(ask2.ApprovalID)
	var approvalErr *ApprovalError
	if _, err := agent.WaitForApproval(context.Background(), ask2.ApprovalID, 10*time.Second, 500*time.Millisecond); !errors.As(err, &approvalErr) || approvalErr.Status != "rejected" {
		t.Fatalf("rejected: %v", err)
	}
}

func TestAgentBlocksListedAndLifted(t *testing.T) {
	api := startFakeAPI(t)
	c := api.client(t)
	keys, _ := GenerateAgentKey("ES256")
	a, _ := c.Agents.Create(CreateAgentParams{Name: "blocked", AllowedTypes: []string{"LOGIN"}, PublicKey: keys.PublicJWK})
	api.call("/__test/agent-block", map[string]interface{}{"agentId": a.ID, "user": "jane@example.com"})
	blocks, err := c.Agents.ListBlocks(a.ID)
	if err != nil || len(blocks) != 1 || blocks[0].Reason != "not_me" {
		t.Fatalf("blocks: %v %v", blocks, err)
	}
	if err := c.Agents.LiftBlock(a.ID, "jane@example.com"); err != nil {
		t.Fatal(err)
	}
	calls := api.calls()
	if calls[len(calls)-1]["path"] != "/agents/"+a.ID+"/blocks/jane@example.com" && calls[len(calls)-1]["path"] != "/agents/"+a.ID+"/blocks/jane%40example.com" {
		t.Fatalf("path %v", calls[len(calls)-1]["path"])
	}
	if blocks, _ := c.Agents.ListBlocks(a.ID); len(blocks) != 0 {
		t.Fatalf("still blocked: %v", blocks)
	}
}

func TestAgentMandates(t *testing.T) {
	api := startFakeAPI(t)
	c := api.client(t)
	user := "agent-mandates@example.com"
	api.link(user)
	if _, err := c.ActionTypes.Define("PAY_INVOICE", DefineOptions{}); err != nil {
		t.Fatal(err)
	}
	keys, _ := GenerateAgentKey("ES256")
	created, _ := c.Agents.Create(CreateAgentParams{Name: "Mandate bot", AllowedTypes: []string{"PAY_INVOICE"}, PublicKey: keys.PublicJWK})
	agent, _ := NewAgent(AgentConfig{AgentID: created.ID, PrivateKey: keys.PrivateJWK, BaseURL: api.baseURL})
	payment := loadAgentVectors(t).ApprovalToken.Claims["authorization_details"].([]interface{})[0].(map[string]interface{})
	mandate, err := agent.RequestMandate(MandateParams{User: user, Type: "PAY_INVOICE", MaxCount: 2, MaxTotal: map[string]string{"currency": "TRY", "amount": "1000"}, ValidFor: 3600})
	if err != nil || mandate.Status != "pending" || mandate.ChallengeCode != "47" {
		t.Fatalf("mandate: %+v %v", mandate, err)
	}
	var reqs []map[string]interface{}
	resp, _ := http.Get(api.baseURL + "/__test/requests")
	_ = json.NewDecoder(resp.Body).Decode(&reqs)
	resp.Body.Close()
	api.approve(reqs[len(reqs)-1]["id"].(string))
	if m, _ := agent.GetMandate(mandate.MandateID); m.Status != "active" {
		t.Fatalf("not active: %+v", m)
	}
	used, err := agent.RequestApproval(AgentApprovalParams{User: user, Type: "PAY_INVOICE", AuthorizationDetails: []map[string]interface{}{payment}, MandateID: mandate.MandateID})
	if err != nil || used.Status != "approved" || used.Mandate == nil || used.Mandate.UsedCount != 1 {
		t.Fatalf("use: %+v %v", used, err)
	}
	if list, _ := c.Agents.ListMandates(created.ID, user); len(list) != 1 || list[0].MandateID != mandate.MandateID {
		t.Fatalf("list: %+v", list)
	}
	if m, _ := c.Agents.RevokeMandate(created.ID, mandate.MandateID); m.Status != "revoked" {
		t.Fatalf("revoke: %+v", m)
	}
	var apiErr *APIError
	if _, err := agent.RequestApproval(AgentApprovalParams{User: user, Type: "PAY_INVOICE", AuthorizationDetails: []map[string]interface{}{payment}, MandateID: mandate.MandateID}); !errors.As(err, &apiErr) || apiErr.Code != "mandate_revoked" {
		t.Fatalf("after revoke: %v", err)
	}
}
