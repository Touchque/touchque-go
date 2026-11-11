package touchque

// Touchque Login Management API (client.Identity): your customers' accounts,
// roles, business-customer organizations, apps, APIs, connections and the
// tenant itself, from your server with your workspace key.
//
//	found, _ := client.Identity.Users.List(map[string]string{"q": "ayse"})
//	client.Identity.Users.Block("usr_…", "chargeback")
//	job, _ := client.Identity.Imports.Start(map[string]interface{}{"users": []map[string]interface{}{{"email": e, "passwordHash": "$2b$10$…"}}})

import (
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
	CustomDomains *IdentityCrud
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
		CustomDomains: &IdentityCrud{http: h, base: "/identity/custom-domains", listKey: "domains"},
	}
}

// GetTenant returns the tenant (404 not_enabled until it is set up).
// RotateClientSecret gives a Touchque Login application a new client secret,
// shown once in the answer (clientSecret); the old one stops working.
func (r *IdentityResource) RotateClientSecret(clientID string) (map[string]interface{}, error) {
	return r.http.post("/identity/clients/"+idSeg(clientID)+"/rotate-secret", map[string]interface{}{})
}

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

// CheckDomainCertificate checks a verified custom domain's certificate at the sign-in edge now
// (certificate: pending | active | error).
func (r *IdentityResource) CheckDomainCertificate(domainID string) (map[string]interface{}, error) {
	return r.http.post("/identity/custom-domains/"+idSeg(domainID)+"/check-certificate", map[string]interface{}{})
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
