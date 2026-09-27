package touchque

import "net/url"

// AuthResource handles authentication setup and secret management.
type AuthResource struct {
	http *httpClient
}

func newAuthResource(http *httpClient) *AuthResource {
	return &AuthResource{http: http}
}

// GenerateSecret creates a new setup secret for a user.
func (a *AuthResource) GenerateSecret(externalUsername string) (*GenerateSecretResponse, error) {
	res, err := a.http.post("/auth/generate-secret", map[string]interface{}{
		"externalUsername": externalUsername,
	})
	if err != nil {
		return nil, err
	}

	resp := &GenerateSecretResponse{}
	if secret, ok := res["secret"].(string); ok {
		resp.Secret = secret
	}
	if extUser, ok := res["externalUsername"].(string); ok {
		resp.ExternalUsername = extUser
	}
	if expAt, ok := res["expiresAt"].(string); ok {
		resp.ExpiresAt = expAt
	}
	if ttlMs, ok := res["ttlMs"].(float64); ok {
		resp.TTLMs = int(ttlMs)
	}
	if qr, ok := res["qrCodeDataUrl"].(string); ok {
		resp.QRCodeDataURL = qr
	}
	if codes, ok := res["recoveryCodes"].([]interface{}); ok {
		resp.RecoveryCodes = make([]string, len(codes))
		for i, c := range codes {
			if str, ok := c.(string); ok {
				resp.RecoveryCodes[i] = str
			}
		}
	}

	return resp, nil
}

// ResetSecret regenerates a user's secret.
func (a *AuthResource) ResetSecret(externalUsername string) (*ResetSecretResponse, error) {
	res, err := a.http.post("/auth/secret/reset", map[string]interface{}{
		"externalUsername": externalUsername,
	})
	if err != nil {
		return nil, err
	}

	resp := &ResetSecretResponse{}
	if msg, ok := res["message"].(string); ok {
		resp.Message = msg
	}
	if uid, ok := res["userId"].(string); ok {
		resp.UserID = uid
	}
	if sec, ok := res["secret"].(string); ok {
		resp.Secret = sec
	}
	if ext, ok := res["externalUsername"].(string); ok {
		resp.ExternalUsername = ext
	}
	if expAt, ok := res["expiresAt"].(string); ok {
		resp.ExpiresAt = expAt
	}
	if qr, ok := res["qrCodeDataUrl"].(string); ok {
		resp.QRCodeDataURL = qr
	}
	if codes, ok := res["recoveryCodes"].([]interface{}); ok {
		resp.RecoveryCodes = make([]string, len(codes))
		for i, c := range codes {
			if str, ok := c.(string); ok {
				resp.RecoveryCodes[i] = str
			}
		}
	}

	return resp, nil
}

// ValidateSecret validates a setup secret code.
func (a *AuthResource) ValidateSecret(secret string) (*ValidateSecretResponse, error) {
	res, err := a.http.post("/auth/secret/validate", map[string]interface{}{
		"secret": secret,
	})
	if err != nil {
		return nil, err
	}

	resp := &ValidateSecretResponse{}
	if valid, ok := res["valid"].(bool); ok {
		resp.Valid = valid
	}
	if ext, ok := res["externalUsername"].(string); ok {
		resp.ExternalUsername = ext
	}
	if msg, ok := res["message"].(string); ok {
		resp.Message = msg
	}
	if rsn, ok := res["reason"].(string); ok {
		resp.Reason = rsn
	}

	return resp, nil
}

// GetUser looks up a user's link status without sending a push. Useful while
// polling during enrollment: Used flips true and DeviceID is set once the
// mobile app scans the setup secret. Returns an *APIError with StatusCode 404
// if the user is unknown.
func (a *AuthResource) GetUser(externalUsername string) (*GetUserResponse, error) {
	res, err := a.http.get("/users/" + url.PathEscape(externalUsername))
	if err != nil {
		return nil, err
	}

	resp := &GetUserResponse{}
	if ext, ok := res["externalUsername"].(string); ok {
		resp.ExternalUsername = ext
	}
	if dev, ok := res["deviceId"].(string); ok {
		resp.DeviceID = dev
	}
	if used, ok := res["used"].(bool); ok {
		resp.Used = used
	}
	if frozen, ok := res["frozen"].(bool); ok {
		resp.Frozen = frozen
	}
	if c, ok := res["createdAt"].(string); ok {
		resp.CreatedAt = c
	}
	if e, ok := res["expireAt"].(string); ok {
		resp.ExpireAt = e
	}

	return resp, nil
}
