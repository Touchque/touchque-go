package touchque

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"
)

// client.Identity (Touchque Login Management API) against the shared fake API, which checks every signature.
func TestIdentityCalls(t *testing.T) {
	api := startFakeAPI(t)
	defer api.close()
	c := NewClient(&Config{APIKey: "tq_test_key", APISecret: "test_secret", BaseURL: api.baseURL, TimeoutMs: 5000})
	must := func(_ interface{}, err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	must(c.Identity.Users.List(map[string]string{"q": "ada", "limit": "10"}))
	must(c.Identity.Users.Create(map[string]interface{}{"email": "a@x.com", "passwordHash": "$2b$10$abc"}))
	must(c.Identity.Users.Update("usr_1", map[string]interface{}{"appMetadata": map[string]interface{}{"plan": nil}}))
	must(c.Identity.Users.Block("usr_1", "fraud"))
	must(c.Identity.Users.Delete("usr_1"))
	must(c.Identity.Users.ResetMFA("usr_1"))
	must(c.Identity.Users.PasswordReset("usr_1", false))
	must(c.Identity.Users.AddRoles("usr_1", []string{"rol_1"}, "org_1"))
	must(c.Identity.Users.RemoveRole("usr_1", "rol_1", "org_1"))
	must(c.Identity.Imports.Start(map[string]interface{}{"users": []map[string]interface{}{{"email": "b@x.com"}}, "upsert": true}))
	must(c.Identity.Organizations.Invite("org_1", map[string]interface{}{"email": "c@x.com", "clientId": "cli", "roleIds": []string{"rol_1"}}))
	roles, err := c.Identity.Roles.List(nil)
	if err != nil || len(roles) != 0 {
		t.Fatalf("roles: %v %v", roles, err)
	}
	must(c.Identity.UpdateTenant(map[string]interface{}{"slug": "acme", "displayName": "Acme"}))
	job, err := c.Identity.Exports.Wait("job_1", time.Millisecond, time.Second)
	if err != nil || job["status"] != "done" {
		t.Fatalf("job: %v %v", job, err)
	}
	must(c.Identity.SetDelivery("email", map[string]interface{}{"provider": "postmark", "from": "login@acme.test", "serverToken": "pm"}))
	must(c.Identity.TestDelivery("sms", "+905321234567"))
	must(c.Identity.SetAttackProtection(map[string]interface{}{"bot": map[string]interface{}{"provider": "turnstile", "siteKey": "k", "secret": "s", "mode": "risky"}}))
	name := "Acme Pay"
	must(c.Identity.SetApproverAppName(&name))
	must(c.Identity.SetCustomDomainOnly(true))
	must(c.Identity.CheckDomainCertificate("dom_1"))
	must(c.Identity.RotateClientSecret("cli_1"))
	must(c.Identity.Users.EndSession("usr_1", "ses_1"))
	if file, err := c.Identity.Exports.File("job_1"); err != nil || file != `{"ok":true}` {
		t.Fatalf("export file: %q %v", file, err)
	}

	var got []string
	var bodies []interface{}
	for _, call := range api.calls() {
		if strings.HasPrefix(call["path"].(string), "/identity") {
			got = append(got, call["method"].(string)+" "+call["url"].(string))
			bodies = append(bodies, call["body"])
		}
	}
	want := []string{
		"GET /identity/users?limit=10&q=ada",
		"POST /identity/users",
		"PATCH /identity/users/usr_1",
		"POST /identity/users/usr_1/block",
		"DELETE /identity/users/usr_1",
		"DELETE /identity/users/usr_1/mfa",
		"POST /identity/users/usr_1/password-reset",
		"POST /identity/users/usr_1/roles",
		"DELETE /identity/users/usr_1/roles/rol_1?organizationId=org_1",
		"POST /identity/users-imports",
		"POST /identity/organizations/org_1/invitations",
		"GET /identity/roles",
		"PUT /identity/tenant",
		"GET /identity/users-exports/job_1",
		"PUT /identity/delivery/email",
		"POST /identity/delivery/sms/test",
		"PUT /identity/attack-protection",
		"PUT /identity/tenant",
		"PUT /identity/tenant",
		"POST /identity/custom-domains/dom_1/check-certificate",
		"POST /identity/clients/cli_1/rotate-secret",
		"DELETE /identity/users/usr_1/sessions/ses_1",
		"GET /identity/users-exports/job_1/file",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("calls:\n%v\nwant\n%v", got, want)
	}
	if !reflect.DeepEqual(bodies[7], map[string]interface{}{"roleIds": []interface{}{"rol_1"}, "organizationId": "org_1"}) {
		t.Fatalf("roles body: %v", bodies[7])
	}
	if !reflect.DeepEqual(bodies[17], map[string]interface{}{"branding": map[string]interface{}{"approverAppName": "Acme Pay"}}) {
		t.Fatalf("approver body: %v", bodies[17])
	}
	if !reflect.DeepEqual(bodies[18], map[string]interface{}{"customDomainOnly": true}) {
		t.Fatalf("custom domain only body: %v", bodies[18])
	}
}

func TestIdentityPasskeyDomain(t *testing.T) {
	api := startFakeAPI(t)
	defer api.close()
	c := NewClient(&Config{APIKey: "tq_test_key", APISecret: "test_secret", BaseURL: api.baseURL, TimeoutMs: 5000})
	if _, err := c.Identity.SetPasskeyDomain("acme.com"); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Identity.SetPasskeyDomain(""); err != nil {
		t.Fatal(err)
	}
	var bodies []interface{}
	for _, call := range api.calls() {
		if call["method"] == "PUT" && call["path"] == "/identity/tenant" {
			bodies = append(bodies, call["body"])
		}
	}
	want := []interface{}{map[string]interface{}{"passkeyDomain": "acme.com"}, map[string]interface{}{"passkeyDomain": nil}}
	if !reflect.DeepEqual(bodies, want) {
		t.Fatalf("passkey domain bodies: %v", bodies)
	}
}

func TestIdentityUserStore(t *testing.T) {
	api := startFakeAPI(t)
	defer api.close()
	c := NewClient(&Config{APIKey: "tq_test_key", APISecret: "test_secret", BaseURL: api.baseURL, TimeoutMs: 5000})
	steps := []func() (map[string]interface{}, error){
		c.Identity.GetUserStore,
		func() (map[string]interface{}, error) {
			return c.Identity.SetUserStore(map[string]interface{}{"url": "https://api.acme.test/touchque/user-store", "enabled": true})
		},
		func() (map[string]interface{}, error) { return c.Identity.TestUserStore("") },
		func() (map[string]interface{}, error) {
			return c.Identity.TestUserStore("https://api.acme.test/user-store?tenant=acme&v=2")
		},
		func() (map[string]interface{}, error) {
			return c.Identity.SetUserStore(map[string]interface{}{"enabled": false})
		},
		c.Identity.RemoveUserStore,
		func() (map[string]interface{}, error) {
			overview, err := c.Identity.CustomDomains.Overview()
			if err == nil && (len(overview.Domains) != 0 || overview.VerifiedDomains != nil) {
				t.Fatalf("overview of an answer without the fields: %+v", overview)
			}
			return nil, err
		},
		func() (map[string]interface{}, error) { return c.Identity.CustomDomains.Verify("dom_1") },
	}
	for _, step := range steps {
		if _, err := step(); err != nil {
			t.Fatal(err)
		}
	}
	var got []string
	var bodies []interface{}
	for _, call := range api.calls() {
		p := call["path"].(string)
		if strings.HasPrefix(p, "/identity/user-store") || strings.HasPrefix(p, "/identity/custom-domains") {
			got = append(got, call["method"].(string)+" "+call["url"].(string))
			bodies = append(bodies, call["body"])
		}
	}
	want := []string{
		"GET /identity/user-store",
		"PUT /identity/user-store",
		"POST /identity/user-store/test",
		"POST /identity/user-store/test",
		"PUT /identity/user-store",
		"DELETE /identity/user-store",
		"GET /identity/custom-domains",
		"POST /identity/custom-domains/dom_1/verify",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("calls: %v", got)
	}
	wantBodies := []interface{}{
		map[string]interface{}{},
		map[string]interface{}{"url": "https://api.acme.test/touchque/user-store", "enabled": true},
		map[string]interface{}{},
		map[string]interface{}{"url": "https://api.acme.test/user-store?tenant=acme&v=2"},
		map[string]interface{}{"enabled": false},
		map[string]interface{}{},
		map[string]interface{}{},
		map[string]interface{}{},
	}
	if !reflect.DeepEqual(bodies, wantBodies) {
		t.Fatalf("bodies: %v", bodies)
	}

	// Touchque Login not in the organization's plan: the gate's 403 maps to the feature sentinels.
	api.opts(map[string]interface{}{"featureRefused": "feature_not_in_plan", "feature": "ciam"})
	_, err := c.Identity.SetUserStore(map[string]interface{}{"enabled": true})
	var apiErr *APIError
	if !errors.Is(err, ErrFeatureNotInPlan) || !errors.As(err, &apiErr) || apiErr.Feature != "ciam" {
		t.Fatalf("feature refusal: %v", err)
	}
	if _, err := c.Identity.SetPasskeyDomain("acme.com"); !errors.Is(err, ErrFeature) {
		t.Fatalf("feature refusal: %v", err)
	}
}

// identityRequest is one request an identityStub received.
type identityRequest struct{ method, url, body string }

// identityAnswer is what an identityStub answers: status and raw JSON body ("" sends none).
type identityAnswer struct {
	status int
	body   string
}

// identityStub answers "METHOD /path" as the Management API does, one answer per call in order,
// the last one again after that.
func identityStub(t *testing.T, answers map[string][]identityAnswer) (*Client, func() []identityRequest) {
	t.Helper()
	var mu sync.Mutex
	var seen []identityRequest
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		key := r.Method + " " + r.URL.Path
		mu.Lock()
		seen = append(seen, identityRequest{r.Method, r.URL.RequestURI(), string(raw)})
		queue := answers[key]
		a := identityAnswer{status: http.StatusNotFound, body: `{"error":"no route"}`}
		if len(queue) > 0 {
			a = queue[0]
			if len(queue) > 1 {
				answers[key] = queue[1:]
			}
		}
		mu.Unlock()
		if a.body != "" {
			w.Header().Set("Content-Type", "application/json")
		}
		w.WriteHeader(a.status)
		_, _ = io.WriteString(w, a.body)
	}))
	t.Cleanup(srv.Close)
	c := NewClient(&Config{APIKey: "tq_test_key", APISecret: "test_secret", BaseURL: srv.URL, TimeoutMs: 5000})
	return c, func() []identityRequest {
		mu.Lock()
		defer mu.Unlock()
		return append([]identityRequest(nil), seen...)
	}
}

// decodeJSON is raw decoded, for comparing an answer with what the SDK returned.
func decodeJSON(t *testing.T, raw string) map[string]interface{} {
	t.Helper()
	var out map[string]interface{}
	if err := json.Unmarshal([]byte(raw), &out); err != nil {
		t.Fatal(err)
	}
	return out
}

// identityRefusal is err as the *APIError the Management API's refusal maps to.
func identityRefusal(t *testing.T, err error, status int, code string) *APIError {
	t.Helper()
	var apiErr *APIError
	if !errors.As(err, &apiErr) {
		t.Fatalf("want *APIError %d %s, got %T %v", status, code, err, err)
	}
	if apiErr.StatusCode != status || apiErr.Data["error"] != code || apiErr.Message != code {
		t.Fatalf("want %d %s, got %d %q %v", status, code, apiErr.StatusCode, apiErr.Message, apiErr.Data)
	}
	if errors.Is(err, ErrFeature) {
		t.Fatalf("%s is not a feature refusal", code)
	}
	return apiErr
}

func TestIdentityPasskeyDomainWire(t *testing.T) {
	set := `{"slug":"acme","issuer":"https://login.acme.com","customDomainOnly":false,"passkeyDomain":"acme.com","signInMethods":{"password":true,"passkey":true,"emailCode":false}}`
	cleared := `{"slug":"acme","issuer":"https://login.acme.com","customDomainOnly":false,"passkeyDomain":null}`
	c, seen := identityStub(t, map[string][]identityAnswer{"PUT /identity/tenant": {{200, set}, {200, cleared}}})

	tenant, err := c.Identity.SetPasskeyDomain("acme.com")
	if err != nil || !reflect.DeepEqual(tenant, decodeJSON(t, set)) {
		t.Fatalf("set: %v %v", tenant, err)
	}
	tenant, err = c.Identity.SetPasskeyDomain("")
	if err != nil || !reflect.DeepEqual(tenant, decodeJSON(t, cleared)) {
		t.Fatalf("cleared: %v %v", tenant, err)
	}
	if v, ok := tenant["passkeyDomain"]; !ok || v != nil {
		t.Fatalf("passkeyDomain after clearing: %v %v", v, ok)
	}
	want := []identityRequest{
		{"PUT", "/identity/tenant", `{"passkeyDomain":"acme.com"}`},
		{"PUT", "/identity/tenant", `{"passkeyDomain":null}`},
	}
	if got := seen(); !reflect.DeepEqual(got, want) {
		t.Fatalf("requests: %v", got)
	}
}

func TestIdentityPasskeyDomainRefusals(t *testing.T) {
	c, _ := identityStub(t, map[string][]identityAnswer{"PUT /identity/tenant": {
		{409, `{"error":"passkeys_exist","field":"passkeyDomain","count":3,"message":"3 customer passkeys belong to the current setting and would stop working"}`},
		{409, `{"error":"not_your_domain","field":"passkeyDomain","message":"acme.com must be one of your verified custom domains, or a domain above one that your organization verified (Organization → Domains)"}`},
		{409, `{"error":"organization_unavailable","field":"passkeyDomain","message":"Your organization’s verified domains could not be read; try again"}`},
		{400, `{"error":"invalid_request","field":"passkeyDomain","message":"passkeyDomain must be a domain like example.com, or null"}`},
		// Touchque Login not set up yet: the PUT would set it up, and that needs a slug.
		{400, `{"error":"invalid_request","field":"slug","message":"slug must be 3–63 lowercase letters, digits or hyphens"}`},
	}})

	_, err := c.Identity.SetPasskeyDomain("")
	refusal := identityRefusal(t, err, 409, "passkeys_exist")
	if refusal.Data["count"] != float64(3) || refusal.Data["field"] != "passkeyDomain" || refusal.Data["message"] == nil {
		t.Fatalf("passkeys_exist: %v", refusal.Data)
	}
	_, err = c.Identity.SetPasskeyDomain("acme.com")
	identityRefusal(t, err, 409, "not_your_domain")
	_, err = c.Identity.SetPasskeyDomain("acme.com")
	identityRefusal(t, err, 409, "organization_unavailable")
	_, err = c.Identity.SetPasskeyDomain("com")
	if refusal := identityRefusal(t, err, 400, "invalid_request"); refusal.Data["field"] != "passkeyDomain" {
		t.Fatalf("invalid_request: %v", refusal.Data)
	}
	_, err = c.Identity.SetPasskeyDomain("acme.com")
	if refusal := identityRefusal(t, err, 400, "invalid_request"); refusal.Data["field"] != "slug" {
		t.Fatalf("before Touchque Login is set up: %v", refusal.Data)
	}
}

func TestIdentityUserStoreWire(t *testing.T) {
	view := `{"url":"https://api.acme.test/touchque/user-store","enabled":true,"active":false,"movedIn":12,` +
		`"lastCall":{"at":"2026-11-17T06:30:00.000Z","event":"user_store.verify_password","ok":false,"status":500,"ms":31,"error":"answered 500"},` +
		`"paused":true,"updatedAt":"2026-11-16T20:00:00.000Z","signing":"Signed like Touchque webhooks: HMAC-SHA256 with your API secret (x-signature); check it with your SDK's webhook verify."}`
	empty := `{"url":null,"enabled":false,"active":false,"movedIn":0,"lastCall":null,"paused":false,"updatedAt":null,"signing":"Signed like Touchque webhooks"}`
	failed := `{"ok":false,"error":"no answer in 5 seconds","ms":5003}`
	c, seen := identityStub(t, map[string][]identityAnswer{
		"GET /identity/user-store":       {{200, empty}, {200, view}},
		"PUT /identity/user-store":       {{201, view}, {200, view}},
		"POST /identity/user-store/test": {{200, failed}, {200, `{"ok":true,"error":null,"ms":48}`}},
		"DELETE /identity/user-store":    {{204, ""}},
	})

	got, err := c.Identity.GetUserStore()
	if err != nil || !reflect.DeepEqual(got, decodeJSON(t, empty)) {
		t.Fatalf("get, none set: %v %v", got, err)
	}
	if got, err = c.Identity.SetUserStore(map[string]interface{}{"url": "https://api.acme.test/touchque/user-store"}); err != nil || !reflect.DeepEqual(got, decodeJSON(t, view)) {
		t.Fatalf("set (201): %v %v", got, err)
	}
	if got, err = c.Identity.SetUserStore(map[string]interface{}{"enabled": false}); err != nil || got["movedIn"] != float64(12) {
		t.Fatalf("set enabled only: %v %v", got, err)
	}
	if got, err = c.Identity.GetUserStore(); err != nil || !reflect.DeepEqual(got, decodeJSON(t, view)) {
		t.Fatalf("get: %v %v", got, err)
	}
	if got, err = c.Identity.TestUserStore(""); err != nil || !reflect.DeepEqual(got, decodeJSON(t, failed)) {
		t.Fatalf("a failed ping is an answer, not an error: %v %v", got, err)
	}
	if got, err = c.Identity.TestUserStore("https://api.acme.test/user-store?tenant=acme&v=2"); err != nil || got["ok"] != true {
		t.Fatalf("ping: %v %v", got, err)
	}
	for i := 0; i < 2; i++ {
		if got, err = c.Identity.RemoveUserStore(); err != nil || got != nil {
			t.Fatalf("remove #%d: %v %v", i+1, got, err)
		}
	}

	requests := seen()
	if len(requests) != 8 {
		t.Fatalf("requests: %v", requests)
	}
	want := []identityRequest{
		{"GET", "/identity/user-store", ""},
		{"PUT", "/identity/user-store", `{"url":"https://api.acme.test/touchque/user-store"}`},
		{"PUT", "/identity/user-store", `{"enabled":false}`},
		{"GET", "/identity/user-store", ""},
		{"POST", "/identity/user-store/test", `{}`},
		{"POST", "/identity/user-store/test", requests[5].body},
		{"DELETE", "/identity/user-store", ""},
		{"DELETE", "/identity/user-store", ""},
	}
	if !reflect.DeepEqual(requests, want) {
		t.Fatalf("requests: %v", requests)
	}
	// The URL to ping goes in the JSON body as given, never in the path or the query.
	if body := decodeJSON(t, requests[5].body); !reflect.DeepEqual(body, map[string]interface{}{"url": "https://api.acme.test/user-store?tenant=acme&v=2"}) {
		t.Fatalf("ping body: %s", requests[5].body)
	}
}

func TestIdentityUserStoreRefusals(t *testing.T) {
	notEnabled := identityAnswer{404, `{"error":"not_enabled","message":"PUT /identity/tenant first"}`}
	c, _ := identityStub(t, map[string][]identityAnswer{
		"PUT /identity/user-store": {
			{409, `{"error":"passwords_off","field":"enabled","message":"Moving users in checks their passwords: turn passwords on first"}`},
			{400, `{"error":"invalid_request","field":"url","message":"url must use https"}`},
		},
		"POST /identity/user-store/test": {{400, `{"error":"invalid_request","field":"url","message":"url is required"}`}},
		"GET /identity/user-store":       {notEnabled},
		"DELETE /identity/user-store":    {notEnabled},
	})

	_, err := c.Identity.SetUserStore(map[string]interface{}{"url": "https://api.acme.test/touchque/user-store", "enabled": true})
	if refusal := identityRefusal(t, err, 409, "passwords_off"); refusal.Data["field"] != "enabled" {
		t.Fatalf("passwords_off: %v", refusal.Data)
	}
	_, err = c.Identity.SetUserStore(map[string]interface{}{"url": "http://api.acme.test/touchque/user-store"})
	if refusal := identityRefusal(t, err, 400, "invalid_request"); refusal.Data["field"] != "url" || refusal.Data["message"] != "url must use https" {
		t.Fatalf("bad url: %v", refusal.Data)
	}
	_, err = c.Identity.TestUserStore("")
	if refusal := identityRefusal(t, err, 400, "invalid_request"); refusal.Data["message"] != "url is required" {
		t.Fatalf("ping with none set: %v", refusal.Data)
	}
	_, err = c.Identity.GetUserStore()
	identityRefusal(t, err, 404, "not_enabled")
	// DELETE answers 204 also when none is set: a 404 is Touchque Login not set up, never swallowed.
	got, err := c.Identity.RemoveUserStore()
	identityRefusal(t, err, 404, "not_enabled")
	if got != nil {
		t.Fatalf("remove refused: %v", got)
	}
}

func TestIdentityCustomDomains(t *testing.T) {
	primary := `{"id":"dom_1","domain":"login.acme.com","status":"verified","primary":true,"proof":"organization_domain","organizationDomain":"acme.com",` +
		`"dns":{"points":"here","cname":["acme.login.touchque.com"],"cloudflareProxy":false,"caaBlocks":false,"problems":[]},"autoCheckUntil":"2026-11-19T20:00:00.000Z"}`
	pending := `{"id":"dom 2/b","domain":"id.acme.io","status":"pending","primary":false,"proof":"txt","organizationDomain":null,` +
		`"records":[{"type":"TXT","name":"_touchque-login.id.acme.io","value":"touchque-login-verification=abc"},{"type":"CNAME","name":"id.acme.io","value":"acme.login.touchque.com"}],` +
		`"dns":null,"autoCheckUntil":"2026-11-20T08:00:00.000Z"}`
	answer := `{"domains":[` + primary + `,` + pending + `],"verifiedDomains":["acme.com"],"slugPasskeys":4}`
	verified := strings.Replace(pending, `"status":"pending"`, `"status":"verified"`, 1)
	c, seen := identityStub(t, map[string][]identityAnswer{
		"GET /identity/custom-domains": {
			{200, answer}, {200, answer}, {200, answer}, {200, answer}, {200, answer},
			{200, `{"domains":[],"verifiedDomains":null,"slugPasskeys":0}`},
			{200, `{"domains":[],"verifiedDomains":[],"slugPasskeys":0}`},
			{404, `{"error":"not_enabled","message":"PUT /identity/tenant first"}`},
		},
		"POST /identity/custom-domains/dom 2/b/verify": {{200, verified}},
		"DELETE /identity/custom-domains/dom_9":        {{404, `{"error":"not_found"}`}},
	})

	overview, err := c.Identity.CustomDomains.Overview()
	if err != nil {
		t.Fatal(err)
	}
	want := &CustomDomainsOverview{
		Domains:         []map[string]interface{}{decodeJSON(t, primary), decodeJSON(t, pending)},
		VerifiedDomains: []string{"acme.com"},
		SlugPasskeys:    4,
	}
	if !reflect.DeepEqual(overview, want) {
		t.Fatalf("overview: %+v", overview)
	}
	// The alias answers the same.
	if alias, err := c.Identity.GetCustomDomains(); err != nil || !reflect.DeepEqual(alias, want) {
		t.Fatalf("GetCustomDomains: %+v %v", alias, err)
	}
	// List as before: the domains alone.
	if domains, err := c.Identity.CustomDomains.List(nil); err != nil || !reflect.DeepEqual(domains, decodeJSON(t, answer)["domains"]) {
		t.Fatalf("List: %v %v", domains, err)
	}
	// No read by id in the API: Get finds the domain in the list.
	if domain, err := c.Identity.CustomDomains.Get("dom 2/b"); err != nil || !reflect.DeepEqual(domain, decodeJSON(t, pending)) {
		t.Fatalf("Get: %v %v", domain, err)
	}
	_, err = c.Identity.CustomDomains.Get("dom_9")
	missing := identityRefusal(t, err, 404, "not_found")
	if message, _ := missing.Data["message"].(string); message == "" {
		t.Fatalf("Get, none with this id: %v", missing.Data)
	}

	if overview, err = c.Identity.CustomDomains.Overview(); err != nil || overview.Domains == nil || len(overview.Domains) != 0 ||
		overview.VerifiedDomains != nil || overview.SlugPasskeys != 0 {
		t.Fatalf("none, your organization's domains unreadable: %+v %v", overview, err)
	}
	if overview, err = c.Identity.CustomDomains.Overview(); err != nil || overview.VerifiedDomains == nil || len(overview.VerifiedDomains) != 0 {
		t.Fatalf("none, your organization verified none: %+v %v", overview, err)
	}
	// A list that cannot be read is that refusal, not a not_found.
	_, err = c.Identity.CustomDomains.Get("dom_1")
	identityRefusal(t, err, 404, "not_enabled")

	if domain, err := c.Identity.CustomDomains.Verify("dom 2/b"); err != nil || !reflect.DeepEqual(domain, decodeJSON(t, verified)) {
		t.Fatalf("Verify: %v %v", domain, err)
	}
	// Get's not_found reads like one from the API.
	_, err = c.Identity.CustomDomains.Delete("dom_9")
	if fromAPI := identityRefusal(t, err, 404, "not_found"); fromAPI.Code != missing.Code || fromAPI.Feature != missing.Feature {
		t.Fatalf("not_found: %+v, from the API %+v", missing, fromAPI)
	}

	list := identityRequest{"GET", "/identity/custom-domains", ""}
	wantRequests := []identityRequest{
		list, list, list, list, list, list, list, list,
		{"POST", "/identity/custom-domains/dom%202%2Fb/verify", `{}`},
		{"DELETE", "/identity/custom-domains/dom_9", ""},
	}
	if got := seen(); !reflect.DeepEqual(got, wantRequests) {
		t.Fatalf("requests: %v", got)
	}
}

// Requests to your user store are signed like Touchque's webhooks, so Webhook.Verify checks them: the
// shared vectors (TestUserStoreVectors) were recorded from the API's own code. A fresh request, its
// timestamp the API's toISOString() with milliseconds, passes the default window, and a replay cache
// refuses its jti a second time. Its password holds what JSON.stringify writes raw (non-ASCII, an
// emoji, <>&, U+2028) and escaped (a quote, a backslash, a tab, an unpaired surrogate).
func TestWebhookVerifiesUserStoreRequests(t *testing.T) {
	c := NewClient(&Config{APIKey: "tq_test_key", APISecret: "test_secret", BaseURL: "https://api.touchque.com"})
	lineSeparator := string(rune(0x2028))
	written := `pässwörd 🔑 \"café\" \\ <>&` + lineSeparator + `\t` + esc("d800")
	read := `pässwörd 🔑 "café" \ <>&` + lineSeparator + "\t" + string(rune(0xFFFD))
	ts := time.Now().UTC().Format("2006-01-02T15:04:05.000Z")
	jti := "9a0c1d2e-3f40-4a5b-8c6d-7e8f9a0b1c2d"
	canonical := `{"email":"ada@acme.test","event":"user_store.verify_password","jti":"` + jti + `","password":"` + written +
		`","tenant":"acme","timestamp":"` + ts + `"}`
	mac := hmac.New(sha256.New, []byte("test_secret"))
	mac.Write([]byte(canonical))
	signature := hex.EncodeToString(mac.Sum(nil))
	raw := `{"event":"user_store.verify_password","tenant":"acme","email":"ada@acme.test","password":"` + written +
		`","timestamp":"` + ts + `","jti":"` + jti + `","signature":"` + signature + `"}`

	opts := WebhookVerifyOptions{ReplayCache: NewMemoryReplayCache()}
	ask, err := c.Webhook.VerifyWithOptions(raw, signature, opts)
	if err != nil {
		t.Fatalf("fresh request: %v", err)
	}
	if ask["event"] != "user_store.verify_password" || ask["tenant"] != "acme" || ask["email"] != "ada@acme.test" || ask["password"] != read {
		t.Fatalf("payload: %q", ask)
	}
	var replay *WebhookReplayError
	if _, err := c.Webhook.VerifyWithOptions(raw, signature, opts); !errors.As(err, &replay) || replay.JTI != jti {
		t.Fatalf("replayed jti: %v", err)
	}
	var sigErr *WebhookSignatureError
	tampered := strings.Replace(raw, "café", "cafe", 1)
	if _, err := c.Webhook.Verify(tampered, signature); !errors.As(err, &sigErr) {
		t.Fatalf("tampered: %v", err)
	}
}
