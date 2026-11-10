package touchque

import (
	"reflect"
	"strings"
	"testing"
	"time"
)

// client.Identity (TouchQue Login Management API) against the shared fake API, which checks every signature.
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
	must(c.Identity.Users.List(map[string]string{"q": "ayse", "limit": "10"}))
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
		"GET /identity/users?limit=10&q=ayse",
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
