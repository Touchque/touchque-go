package touchque

import "net/url"

// AuthResource handles authentication setup and secret management.
type AuthResource struct {
	http *httpClient
}

func newAuthResource(http *httpClient) *AuthResource {
	return &AuthResource{http: http}
}

// GenerateSecretOptions holds every POST /auth/generate-secret field. Use it
// with GenerateSecretWithOptions; GenerateSecret keeps its original signature.
type GenerateSecretOptions struct {
	// ExternalUsername is the user's id in your system.
	ExternalUsername string
	// ClientIP and UserAgent are the end user's, from the request that asks
	// for the QR, as you send them on sign-in (LoginRequestOptions); "" leaves
	// each out. Touchque records them with the secret, never in the QR, and
	// the phone shows where the setup was started before it links
	// (ValidateSecretResponse.SetupContext). Touchque cleans them itself (a
	// port is dropped, a loopback or non-IP address is ignored, the
	// User-Agent loses control characters and is cut at 512 characters) and
	// never refuses the request over them; with neither usable, the QR has
	// no setup context.
	ClientIP  string
	UserAgent string
}

// ResetSecretOptions holds every POST /auth/secret/reset field. Use it with
// ResetSecretWithOptions; ResetSecret keeps its original signature.
type ResetSecretOptions struct {
	// ExternalUsername is the user's id in your system.
	ExternalUsername string
	// ClientIP and UserAgent are the end user's, from the request that asks
	// for the new QR, as in GenerateSecretOptions; "" leaves each out.
	// Touchque records them with the new secret too, as on generate. A reset
	// without them clears the old secret's, so the new QR has no setup
	// context.
	ClientIP  string
	UserAgent string
}

// secretBody is the body of POST /auth/generate-secret and POST
// /auth/secret/reset: clientIp and userAgent by the rules of POST
// /login/request (RequestWithOptions), each only when it is not "".
func secretBody(externalUsername, clientIP, userAgent string) map[string]interface{} {
	body := map[string]interface{}{"externalUsername": externalUsername}
	if clientIP != "" {
		body["clientIp"] = clientIP
	}
	if userAgent != "" {
		body["userAgent"] = userAgent
	}
	return body
}

// GenerateSecret creates a new setup secret for a user. It sends no client
// IP or User-Agent, so its QR has no setup context: use
// GenerateSecretWithOptions from a browser request.
func (a *AuthResource) GenerateSecret(externalUsername string) (*GenerateSecretResponse, error) {
	return a.GenerateSecretWithOptions(GenerateSecretOptions{ExternalUsername: externalUsername})
}

// GenerateSecretWithOptions creates a new setup secret for a user, with the
// end user's ClientIP and UserAgent: the phone shows where the QR was asked
// for before it links.
func (a *AuthResource) GenerateSecretWithOptions(opts GenerateSecretOptions) (*GenerateSecretResponse, error) {
	res, err := a.http.post("/auth/generate-secret", secretBody(opts.ExternalUsername, opts.ClientIP, opts.UserAgent))
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

// ResetSecret regenerates a user's secret. It sends no client IP or
// User-Agent, so the new QR has no setup context (the old one's is cleared):
// use ResetSecretWithOptions from a browser request.
func (a *AuthResource) ResetSecret(externalUsername string) (*ResetSecretResponse, error) {
	return a.ResetSecretWithOptions(ResetSecretOptions{ExternalUsername: externalUsername})
}

// ResetSecretWithOptions regenerates a user's secret, with the end user's
// ClientIP and UserAgent from the request that asks for the new QR: Touchque
// records them for it, as GenerateSecretWithOptions does, and the phone shows
// where the QR was asked for before it links.
func (a *AuthResource) ResetSecretWithOptions(opts ResetSecretOptions) (*ResetSecretResponse, error) {
	res, err := a.http.post("/auth/secret/reset", secretBody(opts.ExternalUsername, opts.ClientIP, opts.UserAgent))
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

// ValidateSecret validates a setup secret code with POST
// /auth/secret/validate, the phone's public call: the Touchque app makes it
// after it scans the QR, before it links. Its SetupContext is where the QR was
// asked for, what the phone shows; nil when the request for the QR named no
// browser (no usable IP address or User-Agent), after a reset without them,
// and for older QRs and servers. Its FarFromPhone compares that place with the
// address of whoever calls validate: called from your server, it compares with
// your server, not the phone.
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
	resp.SetupContext = parseSetupContext(res["setupContext"])

	return resp, nil
}

// parseSetupContext reads the validate answer's setupContext leniently: nil
// when it is missing, null or not an object (no browser named for the QR, a
// reset without one, older QRs and servers); a field that is missing, null or
// of another type stays empty (nil for Location, Device and FarFromPhone), and
// unknown fields are ignored.
func parseSetupContext(v interface{}) *SetupContext {
	m, ok := v.(map[string]interface{})
	if !ok {
		return nil
	}
	sc := &SetupContext{}
	sc.IP, _ = m["ip"].(string)
	if loc, ok := m["location"].(map[string]interface{}); ok {
		l := &SetupLocation{}
		l.City, _ = loc["city"].(string)
		l.Country, _ = loc["country"].(string)
		l.CountryCode, _ = loc["countryCode"].(string)
		sc.Location = l
	}
	if dev, ok := m["device"].(map[string]interface{}); ok {
		d := &SetupDevice{}
		d.Browser, _ = dev["browser"].(string)
		d.OS, _ = dev["os"].(string)
		d.Model, _ = dev["model"].(string)
		sc.Device = d
	}
	sc.RequestedAt, _ = m["requestedAt"].(string)
	if far, ok := m["farFromPhone"].(bool); ok {
		sc.FarFromPhone = &far
	}
	return sc
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
	if dev, ok := res["device"].(map[string]interface{}); ok {
		posture := &DevicePosture{}
		if err := decodeInto(dev, posture); err == nil {
			resp.Device = posture
		}
	}

	return resp, nil
}
