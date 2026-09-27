package touchque

import "net/url"

// WebAuthnResource is the WebAuthn / FIDO2 (passkey) approval path, alongside
// the push + device flow (Login.Verify).
//
// Server-to-server, like every other resource here: the passkey ceremony runs
// in the browser (navigator.credentials.create()/.get(), or @touchque/web);
// your backend collects that JSON and relays it through these methods. There is
// no client-side ceremony in this SDK.
type WebAuthnResource struct {
	http *httpClient
}

func newWebAuthnResource(http *httpClient) *WebAuthnResource {
	return &WebAuthnResource{http: http}
}

// RegisterOptions is step 1 of registering a passkey — options for
// navigator.credentials.create(). discoverable=true registers a resident
// credential (forced UV), the shape a passwordless-primary login uses.
// The raw options object is returned as-is for the browser.
func (w *WebAuthnResource) RegisterOptions(externalUsername string, discoverable bool) (map[string]interface{}, error) {
	body := map[string]interface{}{"externalUsername": externalUsername}
	if discoverable {
		body["discoverable"] = true
	}
	return w.http.post("/webauthn/register/options", body)
}

// RegisterVerify is step 2 — verify the browser's registration response and
// store the credential.
func (w *WebAuthnResource) RegisterVerify(externalUsername string, response map[string]interface{}, label string) (*WebAuthnRegisterVerifyResponse, error) {
	body := map[string]interface{}{"externalUsername": externalUsername, "response": response}
	if label != "" {
		body["label"] = label
	}
	res, err := w.http.post("/webauthn/register/verify", body)
	if err != nil {
		return nil, err
	}
	resp := &WebAuthnRegisterVerifyResponse{}
	if v, ok := res["verified"].(bool); ok {
		resp.Verified = v
	}
	if id, ok := res["credentialId"].(string); ok {
		resp.CredentialID = id
	}
	return resp, nil
}

// AuthenticateOptions is step 1 of approving a pending login with a passkey —
// options for navigator.credentials.get(), scoped to requestID.
func (w *WebAuthnResource) AuthenticateOptions(requestID string) (map[string]interface{}, error) {
	return w.http.post("/webauthn/login/options", map[string]interface{}{"requestId": requestID})
}

// AuthenticateVerify is step 2 — verify the assertion, approving the LoginRequest.
func (w *WebAuthnResource) AuthenticateVerify(requestID string, response map[string]interface{}) (*WebAuthnAuthenticateVerifyResponse, error) {
	res, err := w.http.post("/webauthn/login/verify", map[string]interface{}{"requestId": requestID, "response": response})
	if err != nil {
		return nil, err
	}
	resp := &WebAuthnAuthenticateVerifyResponse{}
	if v, ok := res["success"].(bool); ok {
		resp.Success = v
	}
	if m, ok := res["message"].(string); ok {
		resp.Message = m
	}
	return resp, nil
}

// PrimaryOptions is step 1 of a passwordless-primary login. Requires
// TenantPolicy.passwordlessLoginEnabled. A 404 no_passkey_registered means the
// user has no passkey — fall back to password login.
func (w *WebAuthnResource) PrimaryOptions(externalUsername string) (*WebAuthnPrimaryOptionsResponse, error) {
	res, err := w.http.post("/webauthn/authenticate/primary/options", map[string]interface{}{"externalUsername": externalUsername})
	if err != nil {
		return nil, err
	}
	resp := &WebAuthnPrimaryOptionsResponse{}
	if id, ok := res["attemptId"].(string); ok {
		resp.AttemptID = id
	}
	if o, ok := res["options"].(map[string]interface{}); ok {
		resp.Options = o
	}
	return resp, nil
}

// PrimaryVerify is step 2 of a passwordless-primary login.
func (w *WebAuthnResource) PrimaryVerify(attemptID string, response map[string]interface{}) (*WebAuthnPrimaryVerifyResponse, error) {
	res, err := w.http.post("/webauthn/authenticate/primary/verify", map[string]interface{}{"attemptId": attemptID, "response": response})
	if err != nil {
		return nil, err
	}
	resp := &WebAuthnPrimaryVerifyResponse{}
	if v, ok := res["success"].(bool); ok {
		resp.Success = v
	}
	if v, ok := res["requiresStepUp"].(bool); ok {
		resp.RequiresStepUp = v
	}
	if s, ok := res["externalUsername"].(string); ok {
		resp.ExternalUsername = s
	}
	if s, ok := res["riskScore"].(float64); ok {
		resp.RiskScore = s
	}
	if s, ok := res["requestId"].(string); ok {
		resp.RequestID = s
	}
	return resp, nil
}

// ListCredentials returns a user's registered credentials (metadata only).
func (w *WebAuthnResource) ListCredentials(externalUsername string) ([]WebAuthnCredentialSummary, error) {
	res, err := w.http.get("/webauthn/credentials?externalUsername=" + url.QueryEscape(externalUsername))
	if err != nil {
		return nil, err
	}
	out := []WebAuthnCredentialSummary{}
	raw, ok := res["credentials"].([]interface{})
	if !ok {
		return out, nil
	}
	for _, item := range raw {
		m, ok := item.(map[string]interface{})
		if !ok {
			continue
		}
		c := WebAuthnCredentialSummary{}
		if s, ok := m["id"].(string); ok {
			c.ID = s
		}
		if s, ok := m["credentialId"].(string); ok {
			c.CredentialID = s
		}
		if s, ok := m["deviceType"].(string); ok {
			c.DeviceType = s
		}
		if b, ok := m["backedUp"].(bool); ok {
			c.BackedUp = b
		}
		if s, ok := m["label"].(string); ok {
			c.Label = s
		}
		if s, ok := m["createdAt"].(string); ok {
			c.CreatedAt = s
		}
		if s, ok := m["lastUsedAt"].(string); ok {
			c.LastUsedAt = s
		}
		out = append(out, c)
	}
	return out, nil
}

// DeleteCredential removes a registered credential.
func (w *WebAuthnResource) DeleteCredential(credentialRecordID string) (*WebAuthnDeleteCredentialResponse, error) {
	return w.deleteCredential(credentialRecordID, "")
}

// DeleteCredentialForUser removes a registered credential, scoped to
// externalUsername (recommended over DeleteCredential: without a scope, any
// credential id your API key can reach is deletable).
func (w *WebAuthnResource) DeleteCredentialForUser(credentialRecordID, externalUsername string) (*WebAuthnDeleteCredentialResponse, error) {
	return w.deleteCredential(credentialRecordID, externalUsername)
}

func (w *WebAuthnResource) deleteCredential(credentialRecordID, externalUsername string) (*WebAuthnDeleteCredentialResponse, error) {
	path := "/webauthn/credentials/" + url.PathEscape(credentialRecordID)
	if externalUsername != "" {
		path += "?externalUsername=" + url.QueryEscape(externalUsername)
	}
	res, err := w.http.delete(path)
	if err != nil {
		return nil, err
	}
	resp := &WebAuthnDeleteCredentialResponse{}
	if v, ok := res["deleted"].(bool); ok {
		resp.Deleted = v
	}
	return resp, nil
}
