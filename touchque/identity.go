package touchque

// Touchque Login Management API (client.Identity): your customers' accounts,
// roles, business-customer organizations, apps, APIs, connections and the
// tenant itself, from your server with your workspace key.
//
//	found, _ := client.Identity.Users.List(map[string]string{"q": "ayse"})
//	client.Identity.Users.Block("usr_…", "chargeback")
//	job, _ := client.Identity.Imports.Start(map[string]interface{}{"users": []map[string]interface{}{{"email": e, "passwordHash": "$2b$10$…"}}})

import (
	"net/http"
	"net/url"
	"time"
)

func idSeg(v string) string { return url.PathEscape(v) }

// IdentityResource groups the Touchque Login Management API.
type IdentityResource struct {
	http          *httpClient
	Users         *IdentityUsers
	Imports       *IdentityJobs
	Exports       *IdentityJobs
	Roles         *IdentityCrud
	Organizations *IdentityOrganizations
	Clients       *IdentityCrud
	APIs          *IdentityCrud
	Connections   *IdentityCrud
	CustomDomains *IdentityCustomDomains
}

func newIdentityResource(h *httpClient) *IdentityResource {
	return &IdentityResource{
		http:          h,
		Users:         &IdentityUsers{http: h},
		Imports:       &IdentityJobs{http: h, kind: "imports"},
		Exports:       &IdentityJobs{http: h, kind: "exports"},
		Roles:         &IdentityCrud{http: h, base: "/identity/roles", listKey: "roles"},
		Organizations: &IdentityOrganizations{IdentityCrud{http: h, base: "/identity/organizations", listKey: "organizations"}},
		Clients:       &IdentityCrud{http: h, base: "/identity/clients", listKey: "clients"},
		APIs:          &IdentityCrud{http: h, base: "/identity/apis", listKey: "apis"},
		Connections:   &IdentityCrud{http: h, base: "/identity/connections", listKey: "connections"},
		CustomDomains: &IdentityCustomDomains{IdentityCrud{http: h, base: "/identity/custom-domains", listKey: "domains"}},
	}
}

// RotateClientSecret gives a Touchque Login application a new client secret,
// shown once in the answer (clientSecret); the old one stops working.
func (r *IdentityResource) RotateClientSecret(clientID string) (map[string]interface{}, error) {
	return r.http.post("/identity/clients/"+idSeg(clientID)+"/rotate-secret", map[string]interface{}{})
}

// GetTenant returns the tenant (404 not_enabled until it is set up).
func (r *IdentityResource) GetTenant() (map[string]interface{}, error) {
	return r.http.get("/identity/tenant")
}

// UpdateTenant turns Touchque Login on ({slug, displayName}) or changes its settings.
func (r *IdentityResource) UpdateTenant(body map[string]interface{}) (map[string]interface{}, error) {
	return r.http.put("/identity/tenant", body)
}

// RotateSigningKey retires the tenant's signing key and makes a new one active.
func (r *IdentityResource) RotateSigningKey() (map[string]interface{}, error) {
	return r.http.post("/identity/tenant/signing-keys/rotate", map[string]interface{}{})
}

// SetApproverAppName sets the phone app the hosted pages tell customers to approve on
// ("Approve on the Acme app"). nil: your brand name when the Mobile SDK is set up, else
// Touchque (approverApp in the tenant shows which).
func (r *IdentityResource) SetApproverAppName(name *string) (map[string]interface{}, error) {
	return r.http.put("/identity/tenant", map[string]interface{}{"branding": map[string]interface{}{"approverAppName": name}})
}

// SetCustomDomainOnly serves sign-in only on the primary custom domain: {slug}.login.touchque.com
// redirects page loads there and refuses other calls. Turning it on needs a verified primary
// domain with a working certificate.
func (r *IdentityResource) SetCustomDomainOnly(on bool) (map[string]interface{}, error) {
	return r.http.put("/identity/tenant", map[string]interface{}{"customDomainOnly": on})
}

// SetPasskeyDomain sets the domain customer passkeys are made for, their relying party ID
// (PUT /identity/tenant {"passkeyDomain"}): one of your verified custom domains, or a domain above
// one that your organization verified (Organization → Domains: "acme.com" for "login.acme.com").
// Passkeys made on it or on a host under it belong to it, so they keep working when sign-in moves
// to another host under it. "" sends null: none, a passkey belongs to the host it was made on.
// The answer is the tenant, with the passkeyDomain in use. Set it before customers make passkeys
// on your custom domains: a change (also back to none) that would leave customer passkeys behind
// is refused.
//
// Refusals are *APIError with the code in Data["error"] (also Message) and the field in
// Data["field"]:
//   - 400 invalid_request, field passkeyDomain: not a domain;
//   - 409 not_your_domain: neither a verified custom domain nor a domain above one that your
//     organization verified;
//   - 409 organization_unavailable: your organization's verified domains could not be read; try
//     again;
//   - 409 passkeys_exist: the change would leave customer passkeys behind (Data["count"]);
//   - before Touchque Login is set up for the workspace: 400 invalid_request with field slug (a
//     PUT /identity/tenant then sets it up, which needs a slug: see UpdateTenant).
func (r *IdentityResource) SetPasskeyDomain(domain string) (map[string]interface{}, error) {
	var value interface{}
	if domain != "" {
		value = domain
	}
	return r.http.put("/identity/tenant", map[string]interface{}{"passkeyDomain": value})
}

// CheckDomainCertificate checks a verified custom domain's certificate at the sign-in edge now
// (certificate: pending | active | error).
func (r *IdentityResource) CheckDomainCertificate(domainID string) (map[string]interface{}, error) {
	return r.http.post("/identity/custom-domains/"+idSeg(domainID)+"/check-certificate", map[string]interface{}{})
}

// GetCustomDomains is an alias of CustomDomains.Overview: GET /identity/custom-domains as the API
// answers it, the domains with verifiedDomains and slugPasskeys.
func (r *IdentityResource) GetCustomDomains() (*CustomDomainsOverview, error) {
	return r.CustomDomains.Overview()
}

// Outbox is the delivery log. Message text only in the local dev inbox.
func (r *IdentityResource) Outbox(params map[string]string) (map[string]interface{}, error) {
	return r.http.getWithQuery("/identity/outbox", params)
}

// GetAttackProtection returns the attack protection settings: wrong
// passwords, suspicious addresses, bot challenge, breached passwords,
// new-browser notices, the risk engine.
func (r *IdentityResource) GetAttackProtection() (map[string]interface{}, error) {
	return r.http.get("/identity/attack-protection")
}

// SetAttackProtection changes them (partial; the bot challenge's secret is write-only).
func (r *IdentityResource) SetAttackProtection(settings map[string]interface{}) (map[string]interface{}, error) {
	return r.http.put("/identity/attack-protection", settings)
}

// AttackEvents lists what attack protection caught lately.
func (r *IdentityResource) AttackEvents(params map[string]string) (map[string]interface{}, error) {
	return r.http.getWithQuery("/identity/attack-protection/events", params)
}

// GetDelivery returns the email and SMS providers; secrets never come back (secretsSet).
func (r *IdentityResource) GetDelivery() (map[string]interface{}, error) {
	return r.http.get("/identity/delivery")
}

// SetDelivery sets your own provider for channel "email" (smtp, ses, postmark,
// sendgrid) or "sms" (twilio, netgsm): {"provider", "from", and its fields}.
// A secret left out keeps its stored value.
func (r *IdentityResource) SetDelivery(channel string, provider map[string]interface{}) (map[string]interface{}, error) {
	return r.http.put("/identity/delivery/"+idSeg(channel), provider)
}

// RemoveDelivery goes back to Touchque's transport.
func (r *IdentityResource) RemoveDelivery(channel string) (map[string]interface{}, error) {
	return r.http.delete("/identity/delivery/" + idSeg(channel))
}

// TestDelivery sends one test message through the provider in use.
func (r *IdentityResource) TestDelivery(channel, to string) (map[string]interface{}, error) {
	return r.http.post("/identity/delivery/"+idSeg(channel)+"/test", map[string]interface{}{"to": to})
}

// GetUserStore reads how your customers move in from your own user database
// (GET /identity/user-store): url (nil until set), enabled, active (asked: enabled and passwords
// on), movedIn (accounts made from it so far), lastCall ({at, event, ok, status, ms, error}, nil
// before the first), paused (5 failed calls in a row pause it for a minute), updatedAt and
// signing. For an address with no account yet, Touchque POSTs user_store.verify_password
// {email, password} (a password sign-in) or user_store.get_user {email} (a password reset, an
// email-code sign-in or a sign-up) to url, with tenant, timestamp and jti, signed like its
// webhooks: check each with Webhook.Verify. Answer 200 {"user": {"id", "email", "emailVerified",
// "name", …}} or {"user": null} (the same for an unknown address and a wrong password) within
// 5 seconds.
func (r *IdentityResource) GetUserStore() (map[string]interface{}, error) {
	return r.http.get("/identity/user-store")
}

// SetUserStore sets the endpoint and whether it is asked (PUT /identity/user-store), both
// optional: "url" (https, no user name or password in it; left out, the one set stays) and
// "enabled" (left out, it keeps its value: true for a new endpoint). The answer is GetUserStore's.
// Refusals are *APIError with the code in Data["error"]: 409 passwords_off when it would be on
// while passwords are off, 400 invalid_request (Data["field"] url or enabled).
func (r *IdentityResource) SetUserStore(store map[string]interface{}) (map[string]interface{}, error) {
	return r.http.put("/identity/user-store", store)
}

// TestUserStore sends one signed user_store.ping to url, without saving it, or to the endpoint
// set when url is "" (POST /identity/user-store/test {"url"} or {}): {ok, error, ms}. A ping that
// failed is ok false with error ("answered 500", "no answer in 5 seconds"…), not a Go error;
// 400 invalid_request (Data["field"] url) when url is unusable, or "" with none set.
func (r *IdentityResource) TestUserStore(url string) (map[string]interface{}, error) {
	body := map[string]interface{}{}
	if url != "" {
		body["url"] = url
	}
	return r.http.post("/identity/user-store/test", body)
}

// RemoveUserStore stops asking your user database and forgets the endpoint
// (DELETE /identity/user-store); accounts already moved in stay. The answer is 204, so the map
// is nil, also when none was set: calling it again is no error. A 404 not_enabled means
// Touchque Login is not set up.
func (r *IdentityResource) RemoveUserStore() (map[string]interface{}, error) {
	return r.http.delete("/identity/user-store")
}

// IdentityUsers is a tenant's customer accounts.
type IdentityUsers struct{ http *httpClient }

// List searches: q, blocked, emailVerified, connection, organization, limit, cursor.
func (u *IdentityUsers) List(params map[string]string) (map[string]interface{}, error) {
	return u.http.getWithQuery("/identity/users", params)
}

func (u *IdentityUsers) Get(userID string) (map[string]interface{}, error) {
	return u.http.get("/identity/users/" + idSeg(userID))
}

// Create adds a customer: email and password, passwordHash (bcrypt/argon2),
// customPasswordHash, emailVerified, name, givenName, familyName, phone,
// locale, userMetadata, appMetadata, sendVerificationEmail.
func (u *IdentityUsers) Create(user map[string]interface{}) (map[string]interface{}, error) {
	return u.http.post("/identity/users", user)
}

// Update changes a customer; metadata is merged and a key set to nil is removed.
func (u *IdentityUsers) Update(userID string, changes map[string]interface{}) (map[string]interface{}, error) {
	return u.http.patch("/identity/users/"+idSeg(userID), changes)
}

// Delete erases the account and every workspace row that names it (KVKK/GDPR).
func (u *IdentityUsers) Delete(userID string) (map[string]interface{}, error) {
	return u.http.delete("/identity/users/" + idSeg(userID))
}

// Block signs the customer out everywhere and stops their sign-ins.
func (u *IdentityUsers) Block(userID, reason string) (map[string]interface{}, error) {
	body := map[string]interface{}{}
	if reason != "" {
		body["reason"] = reason
	}
	return u.http.post("/identity/users/"+idSeg(userID)+"/block", body)
}

func (u *IdentityUsers) Unblock(userID string) (map[string]interface{}, error) {
	return u.http.post("/identity/users/"+idSeg(userID)+"/unblock", map[string]interface{}{})
}

// Export returns everything about the person (KVKK/GDPR access request); never hashes.
func (u *IdentityUsers) Export(userID string) (map[string]interface{}, error) {
	return u.http.get("/identity/users/" + idSeg(userID) + "/export")
}

func (u *IdentityUsers) Sessions(userID string) (map[string]interface{}, error) {
	return u.http.get("/identity/users/" + idSeg(userID) + "/sessions")
}

// EndSession signs the person out of one session (the others stay).
func (u *IdentityUsers) EndSession(userID, sessionID string) (map[string]interface{}, error) {
	return u.http.delete("/identity/users/" + idSeg(userID) + "/sessions/" + idSeg(sessionID))
}

func (u *IdentityUsers) SignOutEverywhere(userID string) (map[string]interface{}, error) {
	return u.http.delete("/identity/users/" + idSeg(userID) + "/sessions")
}

// ResetMFA removes passkeys, unlinks the Touchque app, turns email codes off and signs out everywhere.
func (u *IdentityUsers) ResetMFA(userID string) (map[string]interface{}, error) {
	return u.http.delete("/identity/users/" + idSeg(userID) + "/mfa")
}

// ConnectedAccounts lists accounts at providers whose tokens the vault keeps
// for the user (connections with tokenVault on).
func (u *IdentityUsers) ConnectedAccounts(userID string) (map[string]interface{}, error) {
	return u.http.get("/identity/users/" + idSeg(userID) + "/connected-accounts")
}

// DisconnectAccount deletes the stored tokens: apps stop using the account
// for the user; signing in with it stays.
func (u *IdentityUsers) DisconnectAccount(userID, accountID string) (map[string]interface{}, error) {
	return u.http.delete("/identity/users/" + idSeg(userID) + "/connected-accounts/" + idSeg(accountID))
}

func (u *IdentityUsers) UnlinkIdentity(userID, identityID string, force bool) (map[string]interface{}, error) {
	q := ""
	if force {
		q = "?force=true"
	}
	return u.http.delete("/identity/users/" + idSeg(userID) + "/identities/" + idSeg(identityID) + q)
}

func (u *IdentityUsers) SendVerificationEmail(userID, returnTo string) (map[string]interface{}, error) {
	body := map[string]interface{}{}
	if returnTo != "" {
		body["returnTo"] = returnTo
	}
	return u.http.post("/identity/users/"+idSeg(userID)+"/verification-email", body)
}

// PasswordReset emails a password link; with sendEmail false the link comes back for you to deliver.
func (u *IdentityUsers) PasswordReset(userID string, sendEmail bool) (map[string]interface{}, error) {
	return u.http.post("/identity/users/"+idSeg(userID)+"/password-reset", map[string]interface{}{"sendEmail": sendEmail})
}

func (u *IdentityUsers) Roles(userID string) (map[string]interface{}, error) {
	return u.http.get("/identity/users/" + idSeg(userID) + "/roles")
}

// AddRoles gives roles tenant-wide, or inside organizationID when it is not empty.
func (u *IdentityUsers) AddRoles(userID string, roleIDs []string, organizationID string) (map[string]interface{}, error) {
	body := map[string]interface{}{"roleIds": roleIDs}
	if organizationID != "" {
		body["organizationId"] = organizationID
	}
	return u.http.post("/identity/users/"+idSeg(userID)+"/roles", body)
}

func (u *IdentityUsers) RemoveRole(userID, roleID, organizationID string) (map[string]interface{}, error) {
	q := ""
	if organizationID != "" {
		q = "?organizationId=" + url.QueryEscape(organizationID)
	}
	return u.http.delete("/identity/users/" + idSeg(userID) + "/roles/" + idSeg(roleID) + q)
}

func (u *IdentityUsers) Logs(userID string) (map[string]interface{}, error) {
	return u.http.get("/identity/users/" + idSeg(userID) + "/logs")
}

// IdentityJobs runs bulk imports and exports in the background.
type IdentityJobs struct {
	http *httpClient
	kind string
}

// Start: imports {users, upsert}; exports {format: "csv" | "json"}.
func (j *IdentityJobs) Start(body map[string]interface{}) (map[string]interface{}, error) {
	return j.http.post("/identity/users-"+j.kind, body)
}

func (j *IdentityJobs) Get(jobID string) (map[string]interface{}, error) {
	return j.http.get("/identity/users-" + j.kind + "/" + idSeg(jobID))
}

// File is the finished export (CSV or JSON lines), as text.
func (j *IdentityJobs) File(jobID string) (string, error) {
	return j.http.getText("/identity/users-" + j.kind + "/" + idSeg(jobID) + "/file")
}

// Wait polls until the job is done or failed (or timeout passes).
func (j *IdentityJobs) Wait(jobID string, interval, timeout time.Duration) (map[string]interface{}, error) {
	end := time.Now().Add(timeout)
	for {
		job, err := j.Get(jobID)
		if err != nil || job["status"] != "running" || time.Now().After(end) {
			return job, err
		}
		time.Sleep(interval)
	}
}

// IdentityCrud is list, get, create, update and delete for one kind of object.
type IdentityCrud struct {
	http    *httpClient
	base    string
	listKey string
}

func (c *IdentityCrud) List(params map[string]string) ([]interface{}, error) {
	out, err := c.http.getWithQuery(c.base, params)
	if err != nil {
		return nil, err
	}
	list, _ := out[c.listKey].([]interface{})
	if list == nil {
		list = []interface{}{}
	}
	return list, nil
}

func (c *IdentityCrud) Get(id string) (map[string]interface{}, error) {
	return c.http.get(c.base + "/" + idSeg(id))
}

func (c *IdentityCrud) Create(body map[string]interface{}) (map[string]interface{}, error) {
	return c.http.post(c.base, body)
}

func (c *IdentityCrud) Update(id string, body map[string]interface{}) (map[string]interface{}, error) {
	return c.http.patch(c.base+"/"+idSeg(id), body)
}

func (c *IdentityCrud) Delete(id string) (map[string]interface{}, error) {
	return c.http.delete(c.base + "/" + idSeg(id))
}

// IdentityOrganizations is business customers: members, connections, invitations.
type IdentityOrganizations struct{ IdentityCrud }

func (o *IdentityOrganizations) Members(orgID string) (map[string]interface{}, error) {
	return o.http.get(o.base + "/" + idSeg(orgID) + "/members")
}

func (o *IdentityOrganizations) AddMembers(orgID string, userIDs []string) (map[string]interface{}, error) {
	return o.http.post(o.base+"/"+idSeg(orgID)+"/members", map[string]interface{}{"userIds": userIDs})
}

func (o *IdentityOrganizations) RemoveMember(orgID, userID string) (map[string]interface{}, error) {
	return o.http.delete(o.base + "/" + idSeg(orgID) + "/members/" + idSeg(userID))
}

func (o *IdentityOrganizations) SetConnections(orgID string, connections []map[string]interface{}) (map[string]interface{}, error) {
	return o.http.put(o.base+"/"+idSeg(orgID)+"/connections", map[string]interface{}{"connections": connections})
}

func (o *IdentityOrganizations) Invitations(orgID string) (map[string]interface{}, error) {
	return o.http.get(o.base + "/" + idSeg(orgID) + "/invitations")
}

// Invite sends an invitation: {email, clientId, roleIds?, inviterName?, sendEmail?}.
// The link opens the app's sign-in route (initiateLoginUri) with organization and invitation.
func (o *IdentityOrganizations) Invite(orgID string, invitation map[string]interface{}) (map[string]interface{}, error) {
	return o.http.post(o.base+"/"+idSeg(orgID)+"/invitations", invitation)
}

func (o *IdentityOrganizations) RevokeInvitation(orgID, invitationID string) (map[string]interface{}, error) {
	return o.http.delete(o.base + "/" + idSeg(orgID) + "/invitations/" + idSeg(invitationID))
}

// IdentityCustomDomains is your own sign-in domains (login.acme.com): List, Overview, Get,
// Create ({"domain"}; the DNS records to add are in the answer), Verify, Update ({"primary": true}
// makes a verified domain the issuer) and Delete. CheckDomainCertificate (on client.Identity) checks
// a verified domain's certificate.
type IdentityCustomDomains struct{ IdentityCrud }

// CustomDomainsOverview is GET /identity/custom-domains as the API answers it.
type CustomDomainsOverview struct {
	// Domains are the custom domains, each as List returns it: id, domain, status, primary, proof,
	// organizationDomain, certificate, records, dns (what its DNS said at the last check, nil
	// before the first), autoCheckUntil, createdAt. Empty, not nil, when there are none.
	Domains []map[string]interface{} `json:"domains"`
	// VerifiedDomains are the domains your organization verified (Organization → Domains): nil
	// when they could not be read, empty when it verified none.
	VerifiedDomains []string `json:"verifiedDomains"`
	// SlugPasskeys counts the customer passkeys made on {slug}.login.touchque.com: they belong to
	// that name and never work on a custom domain.
	SlugPasskeys int `json:"slugPasskeys"`
}

// Overview returns the custom domains with your organization's verified domains and the passkeys
// made on {slug}.login.touchque.com (GET /identity/custom-domains); List returns the domains alone.
func (d *IdentityCustomDomains) Overview() (*CustomDomainsOverview, error) {
	out, err := d.http.get(d.base)
	if err != nil {
		return nil, err
	}
	overview := &CustomDomainsOverview{Domains: []map[string]interface{}{}}
	domains, _ := out["domains"].([]interface{})
	for _, item := range domains {
		if domain, ok := item.(map[string]interface{}); ok {
			overview.Domains = append(overview.Domains, domain)
		}
	}
	if verified, ok := out["verifiedDomains"].([]interface{}); ok {
		overview.VerifiedDomains = make([]string, 0, len(verified))
		for _, item := range verified {
			if domain, ok := item.(string); ok {
				overview.VerifiedDomains = append(overview.VerifiedDomains, domain)
			}
		}
	}
	if n, ok := out["slugPasskeys"].(float64); ok {
		overview.SlugPasskeys = int(n)
	}
	return overview, nil
}

// Get returns the custom domain with this id, found in List: the API has no read by id. When
// there is none, the error is the API's own 404: an *APIError with StatusCode 404 and "not_found"
// in Data["error"] and Message.
func (d *IdentityCustomDomains) Get(id string) (map[string]interface{}, error) {
	domains, err := d.List(nil)
	if err != nil {
		return nil, err
	}
	for _, item := range domains {
		if domain, ok := item.(map[string]interface{}); ok && domain["id"] == id {
			return domain, nil
		}
	}
	return nil, &APIError{
		StatusCode: http.StatusNotFound,
		Message:    "not_found",
		Data:       map[string]interface{}{"error": "not_found", "message": "No custom domain with this id"},
	}
}

// Verify checks the domain now (POST /identity/custom-domains/{id}/verify): its DNS TXT record
// until it is verified (a domain on one that your organization verified needs none) and what its
// DNS says (dns). The answer is the domain.
func (d *IdentityCustomDomains) Verify(id string) (map[string]interface{}, error) {
	return d.http.post(d.base+"/"+idSeg(id)+"/verify", map[string]interface{}{})
}
