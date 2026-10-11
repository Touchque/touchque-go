package touchque

import (
	"encoding/json"
	"errors"
	"io"
	"log"
	"mime"
	"net/http"
	"strconv"
	"strings"
	"sync"
)

// NewRelayHandler serves the relay routes every partner backend needs for
// classic push 2FA, offline sign and passkeys — the routes @touchque/web
// calls — so you do not hand-write them. Nothing here is partner-specific
// except how you resolve the signed-in user (UserID) and what you do once
// someone is authenticated (OnAuthenticated).
//
//	mux.Handle("/touchque/", http.StripPrefix("/touchque", touchque.NewRelayHandler(tq, touchque.RelayOptions{
//	    UserID:    func(r *http.Request) string { return sessionUser(r) },
//	    LoginUser: func(r *http.Request) string { return passwordVerifiedUser(r) },
//	    OnAuthenticated: func(w http.ResponseWriter, r *http.Request, info touchque.AuthenticatedInfo) error {
//	        return startSession(w, info.ExternalUsername)
//	    },
//	})))
//
// Routes (relative to the mount point):
//
//	POST   /enroll/start                  (auth required) -> GenerateSecretResponse
//	GET    /enroll/status                 (auth required) -> {"linked", "used", "deviceId"}
//	POST   /login                         (pre-auth) -> 202 {"touchque": step, "token"} until approved (same contract as Require)
//	POST   /offline/challenge             (pre-auth, body.externalUsername) -> QR for a phone with no internet
//	POST   /offline/verify                (pre-auth, body.challengeId/code)
//	POST   /offline/totp                  (pre-auth, body.externalUsername/code) -> time-based code fallback
//	POST   /passkey/authenticate/options  (pre-auth, body.email)
//	POST   /passkey/authenticate/verify   (pre-auth, body.attemptId/response)
//	POST   /passkey/login/options         (pre-auth, body.requestId — approve a pending 2FA request)
//	POST   /passkey/login/verify          (pre-auth, body.requestId/response)
//	POST   /passkey/register/options      (auth required)
//	POST   /passkey/register/verify       (auth required, body.response/label)
//	GET    /passkey/credentials           (auth required)
//	DELETE /passkey/credentials/{id}      (auth required)
//
// "Auth required" routes answer 401 UNAUTHORIZED_FOR_2FA when UserID returns
// "" — put your own session middleware in front of the handler (or have
// UserID itself check and return "").
//
// Pre-auth routes are rate limited per IP and per username by default
// (RateLimit), and TouchQue itself caps approval pushes per user. Set
// LoginUser so POST /login and the offline routes only work for a user who
// already passed YOUR first factor (password step): then nobody can make
// TouchQue push to, or lock out, an arbitrary user through your server. The
// offline routes are OFF until you do (or explicitly opt out with
// AllowOfflineWithoutFirstFactor): with the username taken from the body,
// anyone could burn a user's offline attempts and lock them out.
//
// JSON request bodies are read only with Content-Type application/json and
// are limited to 100 KiB.
//
// NewRelayHandler panics when opts.UserID is nil.
func NewRelayHandler(client *Client, opts RelayOptions) http.Handler {
	if opts.UserID == nil {
		// Fail at wiring time, not per request: there is no safe default.
		panic("touchque.NewRelayHandler: RelayOptions.UserID is required — resolve the user from your server-side session")
	}
	h := &relayHandler{
		client:         client,
		opts:           opts,
		actionType:     opts.ActionType,
		ipOf:           opts.IP,
		offlineEnabled: opts.LoginUser != nil || opts.AllowOfflineWithoutFirstFactor,
	}
	if h.actionType == "" {
		h.actionType = "LOGIN"
	}
	if h.ipOf == nil {
		h.ipOf = defaultRelayIP
	}
	if opts.RateLimit == nil || !opts.RateLimit.Disabled {
		var rl RateLimitOptions
		if opts.RateLimit != nil {
			rl = *opts.RateLimit
		}
		h.limiter = newFixedWindowLimiter(rl)
	}

	if opts.LoginUser == nil {
		warnRelayPreAuth.Do(func() {
			tail := "; the offline routes are disabled until you set it"
			if h.offlineEnabled {
				tail = ", and so do the offline routes"
			}
			log.Printf("[TouchQue] NewRelayHandler: POST /login takes the username from the request body%s."+
				" Set RelayOptions.LoginUser to bind them to your first factor (password step) so they cannot be used against arbitrary users.", tail)
		})
	}

	mux := http.NewServeMux()
	mux.HandleFunc("POST /enroll/start", h.withBody(h.enrollStart))
	mux.HandleFunc("GET /enroll/status", h.enrollStatus)
	mux.HandleFunc("POST /login", h.withBody(h.login))
	mux.HandleFunc("POST /offline/challenge", h.withBody(h.offlineChallenge))
	mux.HandleFunc("POST /offline/verify", h.withBody(h.offlineVerify))
	mux.HandleFunc("POST /offline/totp", h.withBody(h.offlineTotp))
	mux.HandleFunc("POST /passkey/authenticate/options", h.withBody(h.passkeyPrimaryOptions))
	mux.HandleFunc("POST /passkey/authenticate/verify", h.withBody(h.passkeyPrimaryVerify))
	mux.HandleFunc("POST /passkey/login/options", h.withBody(h.passkeyApproveOptions))
	mux.HandleFunc("POST /passkey/login/verify", h.withBody(h.passkeyApproveVerify))
	mux.HandleFunc("POST /passkey/register/options", h.withBody(h.passkeyRegisterOptions))
	mux.HandleFunc("POST /passkey/register/verify", h.withBody(h.passkeyRegisterVerify))
	mux.HandleFunc("GET /passkey/credentials", h.passkeyListCredentials)
	mux.HandleFunc("DELETE /passkey/credentials/{id}", h.withBody(h.passkeyDeleteCredential))
	return mux
}

// RelayOptions configures NewRelayHandler.
type RelayOptions struct {
	// UserID resolves the signed-in user's identifier for the "auth required"
	// routes (enrollment, passkey registration/management). Return "" when
	// there is no signed-in user — the route answers 401. Required:
	// NewRelayHandler panics when it is nil.
	UserID func(*http.Request) string

	// LoginUser is STRONGLY RECOMMENDED: the user who has already passed your
	// first factor (e.g. the password step stored in the session). When set,
	// POST /login, POST /offline/challenge and POST /offline/totp use this
	// user and IGNORE any username in the request body; when it returns ""
	// they answer 401 FIRST_FACTOR_REQUIRED. POST /offline/verify and
	// POST /passkey/login/verify then only open a session when TouchQue's
	// user matches it. Without it, anyone can type any user's email and make
	// TouchQue push to that user's phone (push-bombing) or spend that user's
	// offline attempts.
	LoginUser func(*http.Request) string

	// RateLimit configures the built-in limits for the pre-auth routes (per
	// client IP and per username, per route). nil means the defaults: 20
	// requests per IP and 5 per username per minute. Set Disabled to turn it
	// off if you already rate limit in front of this handler. The IP func
	// must return the real client address.
	RateLimit *RateLimitOptions

	// AllowOfflineWithoutFirstFactor: the offline routes (/offline/challenge,
	// /offline/verify, /offline/totp) answer 403 OFFLINE_REQUIRES_FIRST_FACTOR
	// unless LoginUser is set. Set this to true only if you really want them
	// to trust the username in the request body (e.g. your own gateway
	// already authenticated the user).
	AllowOfflineWithoutFirstFactor bool

	// ActionType is the action type used by POST /login and the offline
	// routes. Default "LOGIN".
	ActionType string

	// Details is optional transaction context for the POST /login push and
	// the offline QR, shown on the approval screen. Build it from your own
	// server-side state — anything read from the request body is
	// attacker-controlled.
	Details func(*http.Request) []LoginDetail

	// OnAuthenticated is called right before the handler writes its own
	// success response for POST /login (once approved), the offline routes
	// and the passkey sign-in routes (once verified) — the one place a
	// partner almost always needs to do something (open a session cookie,
	// etc.). Set cookies/headers on w here; do not write the body — the
	// handler does that right after. A non-nil error aborts the success
	// response and is answered as an error instead.
	OnAuthenticated func(w http.ResponseWriter, r *http.Request, info AuthenticatedInfo) error

	// IP is the end user's address, used for the per-IP rate limit and shown
	// on the phone (default: the host part of r.RemoteAddr — set this
	// explicitly behind a reverse proxy, from your trusted X-Forwarded-For
	// hop).
	IP func(*http.Request) string
}

// AuthenticatedVia says which relay route authenticated the user.
type AuthenticatedVia string

const (
	ViaLogin       AuthenticatedVia = "login"
	ViaPasskey     AuthenticatedVia = "passkey"
	ViaOffline     AuthenticatedVia = "offline"
	ViaOfflineTotp AuthenticatedVia = "offline-totp"
)

// AuthenticatedInfo is passed to RelayOptions.OnAuthenticated.
// ExternalUsername always comes from TouchQue or your LoginUser func, never
// from the request body.
type AuthenticatedInfo struct {
	ExternalUsername string
	RequestID        string
	Via              AuthenticatedVia
}

const relayMaxBodyBytes = 100 << 10

var warnRelayPreAuth sync.Once

type relayHandler struct {
	client         *Client
	opts           RelayOptions
	actionType     string
	ipOf           func(*http.Request) string
	limiter        *fixedWindowLimiter
	offlineEnabled bool
}

// defaultRelayIP is the host part of r.RemoteAddr (the port changes per
// connection, which would defeat the per-IP limit).
func defaultRelayIP(r *http.Request) string {
	return hostOnly(r.RemoteAddr)
}

type relayBody map[string]interface{}

// str mirrors JavaScript's String(body[key] || ""): falsy values are "".
func (b relayBody) str(key string) string {
	switch v := b[key].(type) {
	case string:
		return v
	case float64:
		if v == 0 {
			return ""
		}
		return strconv.FormatFloat(v, 'f', -1, 64)
	case bool:
		if v {
			return "true"
		}
	}
	return ""
}

// nonEmptyString returns body[key] only when it is a non-empty JSON string.
func (b relayBody) nonEmptyString(key string) string {
	s, _ := b[key].(string)
	return s
}

func (b relayBody) object(key string) map[string]interface{} {
	m, _ := b[key].(map[string]interface{})
	return m
}

// withBody parses a JSON request body (Content-Type application/json only,
// at most relayMaxBodyBytes) before calling next. Any other content type
// yields an empty body, as express.json() does.
func (h *relayHandler) withBody(next func(http.ResponseWriter, *http.Request, relayBody)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		body := relayBody{}
		if mt, _, err := mime.ParseMediaType(r.Header.Get("Content-Type")); err == nil && mt == "application/json" && r.Body != nil {
			raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, relayMaxBodyBytes))
			if err != nil {
				var tooLarge *http.MaxBytesError
				if errors.As(err, &tooLarge) {
					writeRelayJSON(w, http.StatusRequestEntityTooLarge, map[string]interface{}{"error": "payload_too_large"})
					return
				}
				writeRelayJSON(w, http.StatusBadRequest, map[string]interface{}{"error": "invalid_body"})
				return
			}
			if len(strings.TrimSpace(string(raw))) > 0 {
				var parsed interface{}
				if err := json.Unmarshal(raw, &parsed); err != nil {
					writeRelayJSON(w, http.StatusBadRequest, map[string]interface{}{"error": "invalid_json"})
					return
				}
				switch v := parsed.(type) {
				case map[string]interface{}:
					body = v
				case []interface{}:
					// An array is valid JSON but names no fields.
				default:
					writeRelayJSON(w, http.StatusBadRequest, map[string]interface{}{"error": "invalid_json"})
					return
				}
			}
		}
		next(w, r, body)
	}
}

func writeRelayJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// sendAuthResultError is the same status-code mapping as the Node router's
// sendAuthResultError — kept in sync.
func sendAuthResultError(w http.ResponseWriter, err error) {
	var rejected *RejectedError
	var passkey *PasskeyRequiredError
	var timeout *TimeoutError
	var apiErr *APIError
	switch {
	case errors.As(err, &rejected):
		writeRelayJSON(w, http.StatusForbidden, map[string]interface{}{"error": "2FA_REJECTED", "message": "User rejected the 2FA request on their device."})
	case errors.As(err, &passkey):
		writeRelayJSON(w, http.StatusConflict, map[string]interface{}{"error": "PASSKEY_REQUIRED", "requestId": passkey.RequestID, "message": "Approve this sign-in with your passkey."})
	case errors.As(err, &timeout):
		writeRelayJSON(w, http.StatusRequestTimeout, map[string]interface{}{"error": "2FA_TIMEOUT", "message": "User did not respond to the 2FA request in time."})
	case errors.As(err, &apiErr) && apiErr.StatusCode < 500:
		// A real API error (e.g. 404 "no linked device for this user") still
		// carries a useful client-range status: surface it. Only a genuine
		// network failure or unexpected error falls through to 503.
		code := dataError(apiErr)
		if code == "" {
			code, _ = apiErr.Data["message"].(string)
		}
		if code == "" {
			code = apiErr.Message
		}
		if code == "" {
			code = "request_failed"
		}
		writeRelayJSON(w, apiErr.StatusCode, map[string]interface{}{"error": code})
	default:
		log.Printf("[TouchQue Relay Error] %v", err)
		writeRelayJSON(w, http.StatusServiceUnavailable, map[string]interface{}{"error": "2FA_UNAVAILABLE", "message": "The 2FA verification service is temporarily unavailable."})
	}
}

// sendRelayError is for plain relay routes (enroll, offline, passkey): a
// client-range TouchQue status is forwarded with its machine-readable code
// only — never TouchQue's internal message text — anything else becomes 502.
func sendRelayError(w http.ResponseWriter, err error) {
	var apiErr *APIError
	if errors.As(err, &apiErr) && apiErr.StatusCode < 500 {
		code := apiErr.Code
		if code == "" {
			code = dataError(apiErr)
		}
		if code == "" {
			code = "request_failed"
		}
		writeRelayJSON(w, apiErr.StatusCode, map[string]interface{}{"error": code})
		return
	}
	writeRelayJSON(w, http.StatusBadGateway, map[string]interface{}{"error": "relay_error"})
}

func apiStatus(err error) int {
	var apiErr *APIError
	if errors.As(err, &apiErr) {
		return apiErr.StatusCode
	}
	return 0
}

// requireUserID answers 401 and returns "" when nobody is signed in.
func (h *relayHandler) requireUserID(w http.ResponseWriter, r *http.Request) string {
	userID := h.opts.UserID(r)
	if userID == "" {
		writeRelayJSON(w, http.StatusUnauthorized, map[string]interface{}{
			"error":   "UNAUTHORIZED_FOR_2FA",
			"message": "Could not find user ID in request. Put your own auth middleware in front of this handler.",
		})
	}
	return userID
}

// offlineAllowed answers 403 and returns false when the offline routes are not enabled.
func (h *relayHandler) offlineAllowed(w http.ResponseWriter) bool {
	if h.offlineEnabled {
		return true
	}
	writeRelayJSON(w, http.StatusForbidden, map[string]interface{}{
		"error":   "OFFLINE_REQUIRES_FIRST_FACTOR",
		"message": "Offline sign-in is disabled: configure LoginUser (or AllowOfflineWithoutFirstFactor) on the TouchQue relay handler.",
	})
	return false
}

// allow answers 429 and returns false when this IP or this user is over the
// limit for route. Both counters are always hit.
// A 1.5 s poll for a 2-minute push is 80 requests: one attempt's worth of polls.
const pollsPerAttempt = 10

func (h *relayHandler) allow(w http.ResponseWriter, r *http.Request, route, user string) bool {
	return h.allowN(w, r, route, user, 1)
}

// allowN is allow with the per-IP budget multiplied by ipFactor.
func (h *relayHandler) allowN(w http.ResponseWriter, r *http.Request, route, user string, ipFactor int) bool {
	if h.limiter == nil {
		return true
	}
	ip := h.ipOf(r)
	if ip == "" {
		ip = "unknown"
	}
	wait := h.limiter.hit("ip|"+route+"|"+ip, h.limiter.perIP*ipFactor)
	if user != "" {
		if uw := h.limiter.hit("user|"+route+"|"+user, h.limiter.perUser); uw > wait {
			wait = uw
		}
	}
	if wait == 0 {
		return true
	}
	w.Header().Set("Retry-After", strconv.Itoa(wait))
	writeRelayJSON(w, http.StatusTooManyRequests, map[string]interface{}{
		"error": "RATE_LIMITED", "message": "Too many attempts. Try again later.", "retryAfter": wait,
	})
	return false
}

// loginUser is who a pre-auth route acts for: the first-factor user when
// LoginUser is configured, otherwise the typed username. It answers the
// request and returns "" when there is none.
func (h *relayHandler) loginUser(w http.ResponseWriter, r *http.Request, body relayBody, field string) string {
	if h.opts.LoginUser != nil {
		u := h.opts.LoginUser(r)
		if u == "" {
			writeRelayJSON(w, http.StatusUnauthorized, map[string]interface{}{"error": "FIRST_FACTOR_REQUIRED", "message": "Sign in with your password first."})
			return ""
		}
		return strings.ToLower(u)
	}
	typed := strings.ToLower(body.str(field))
	if typed == "" {
		writeRelayJSON(w, http.StatusBadRequest, map[string]interface{}{"error": "externalUsername_required"})
	}
	return typed
}

// matchesLoginUser reports whether TouchQue's user is the first-factor user.
func (h *relayHandler) matchesLoginUser(r *http.Request, touchqueUser string) bool {
	expected := h.opts.LoginUser(r)
	return expected != "" && strings.ToLower(expected) == strings.ToLower(touchqueUser)
}

func (h *relayHandler) details(r *http.Request) []LoginDetail {
	if h.opts.Details == nil {
		return nil
	}
	return h.opts.Details(r)
}

func (h *relayHandler) authenticated(w http.ResponseWriter, r *http.Request, info AuthenticatedInfo) error {
	if h.opts.OnAuthenticated == nil {
		return nil
	}
	return h.opts.OnAuthenticated(w, r, info)
}

// ── Classic push 2FA: enrollment ──────────────────────────────────────

func (h *relayHandler) enrollStart(w http.ResponseWriter, r *http.Request, _ relayBody) {
	userID := h.requireUserID(w, r)
	if userID == "" {
		return
	}
	res, err := h.client.Auth.GenerateSecret(userID)
	if err == nil {
		writeRelayJSON(w, http.StatusOK, res)
		return
	}
	// 409: either a QR was issued and not scanned yet (safe to issue a new
	// one — no phone to lose), or a phone is ALREADY linked. Replacing a
	// linked phone must never happen from a plain session: that is exactly
	// how an attacker with a stolen password would swap in their own phone.
	if apiStatus(err) != http.StatusConflict {
		sendRelayError(w, err)
		return
	}
	current, err := h.client.Auth.GetUser(userID)
	if err != nil {
		sendRelayError(w, err)
		return
	}
	if current.Used || current.DeviceID != "" {
		writeRelayJSON(w, http.StatusConflict, map[string]interface{}{"error": "already_linked", "message": "A phone is already linked to this account."})
		return
	}
	reset, err := h.client.Auth.ResetSecret(userID)
	if err != nil {
		sendRelayError(w, err)
		return
	}
	writeRelayJSON(w, http.StatusOK, reset)
}

func (h *relayHandler) enrollStatus(w http.ResponseWriter, r *http.Request) {
	userID := h.requireUserID(w, r)
	if userID == "" {
		return
	}
	u, err := h.client.Auth.GetUser(userID)
	if err != nil {
		if apiStatus(err) == http.StatusNotFound {
			writeRelayJSON(w, http.StatusOK, map[string]interface{}{"linked": false, "used": false, "deviceId": nil})
			return
		}
		sendRelayError(w, err)
		return
	}
	var deviceID interface{}
	if u.DeviceID != "" {
		deviceID = u.DeviceID
	}
	writeRelayJSON(w, http.StatusOK, map[string]interface{}{"linked": u.Used && u.DeviceID != "", "used": u.Used, "deviceId": deviceID})
}

// ── Classic push 2FA: login ───────────────────────────────────────────

func (h *relayHandler) login(w http.ResponseWriter, r *http.Request, body relayBody) {
	user := h.loginUser(w, r, body, "externalUsername")
	if user == "" {
		return
	}
	// Same two-phase contract as Require: 202 with the step (matching number
	// / first-time QR / offline QR) until approved; the page re-sends with
	// X-TouchQue-Token.
	token, offline, code, codeType := guardInputFromRequest(r)
	in := GuardInput{
		User: user, Action: h.actionType, Details: h.details(r),
		IP: h.ipOf(r), UserAgent: r.UserAgent(),
		Token: token, Offline: offline == "1", Code: code, CodeType: codeType,
		// Pre-auth: a typed username proves nothing, so no linking QR unless
		// LoginUser ties this route to the password step.
		NoEnroll: h.opts.LoginUser == nil,
	}
	// Polling an approval already sent is not a new attempt: it has its own,
	// larger per-IP budget and never uses the user's push budget.
	if isStatusPoll(h.client, in) {
		if !h.allowN(w, r, "login-poll", "", pollsPerAttempt) {
			return
		}
	} else if !h.allow(w, r, "login", user) {
		return
	}
	result := runGuard(h.client, in)
	if result.Approved == nil {
		if result.Body.Touchque.RetryAfter > 0 {
			w.Header().Set("Retry-After", strconv.Itoa(result.Body.Touchque.RetryAfter))
		}
		w.Header().Set("Cache-Control", "no-store")
		writeRelayJSON(w, result.Status, result.Body)
		return
	}
	via := ViaLogin
	switch result.Approved.ConfirmedVia {
	case "OFFLINE_TOTP":
		via = ViaOfflineTotp
	case "OFFLINE_CODE":
		via = ViaOffline
	}
	if err := h.authenticated(w, r, AuthenticatedInfo{ExternalUsername: user, RequestID: result.Approved.RequestID, Via: via}); err != nil {
		sendAuthResultError(w, err)
		return
	}
	writeRelayJSON(w, http.StatusOK, map[string]interface{}{"status": "success", "requestId": result.Approved.RequestID, "assurance": result.Approved.Assurance})
}

// ── Offline sign: QR challenge / typed code ──────────────────────────
// The username passed to OnAuthenticated is the one TouchQue returns for the
// challenge/code, never the one in the request body.

func (h *relayHandler) offlineChallenge(w http.ResponseWriter, r *http.Request, body relayBody) {
	if !h.offlineAllowed(w) {
		return
	}
	user := h.loginUser(w, r, body, "externalUsername")
	if user == "" || !h.allow(w, r, "offline-challenge", user) {
		return
	}
	// requestId (the push this QR follows) makes a phone-side rejection kill the QR and carries the number.
	c, err := h.client.Offline.Challenge(OfflineChallengeOptions{
		ExternalUsername: user,
		Type:             h.actionType,
		ClientIP:         h.ipOf(r),
		UserAgent:        r.UserAgent(),
		Details:          h.details(r),
		RequestID:        body.nonEmptyString("requestId"),
	})
	if err != nil {
		sendRelayError(w, err)
		return
	}
	writeRelayJSON(w, http.StatusOK, c)
}

func offlineFailure(res *OfflineVerifyResult, withAttempts bool) (int, map[string]interface{}) {
	status := http.StatusBadRequest
	if res.Reason == "invalid_code" {
		status = http.StatusUnauthorized
	}
	out := map[string]interface{}{"approved": false}
	if res.Reason != "" {
		out["reason"] = res.Reason
	}
	if withAttempts && res.AttemptsLeft > 0 {
		out["attemptsLeft"] = res.AttemptsLeft
	}
	return status, out
}

func (h *relayHandler) offlineVerify(w http.ResponseWriter, r *http.Request, body relayBody) {
	if !h.offlineAllowed(w) || !h.allow(w, r, "offline-verify", "") {
		return
	}
	res, err := h.client.Offline.Verify(body.str("challengeId"), body.str("code"))
	if err != nil {
		sendRelayError(w, err)
		return
	}
	if !res.Approved || res.ExternalUsername == "" {
		status, out := offlineFailure(res, true)
		writeRelayJSON(w, status, out)
		return
	}
	// With a first factor, the code must belong to the user who passed it.
	if h.opts.LoginUser != nil && !h.matchesLoginUser(r, res.ExternalUsername) {
		writeRelayJSON(w, http.StatusUnauthorized, map[string]interface{}{"approved": false, "reason": "invalid_code"})
		return
	}
	if err := h.authenticated(w, r, AuthenticatedInfo{ExternalUsername: res.ExternalUsername, RequestID: res.ChallengeID, Via: ViaOffline}); err != nil {
		sendRelayError(w, err)
		return
	}
	writeRelayJSON(w, http.StatusOK, map[string]interface{}{"status": "success", "approved": true, "requestId": res.ChallengeID})
}

func (h *relayHandler) offlineTotp(w http.ResponseWriter, r *http.Request, body relayBody) {
	if !h.offlineAllowed(w) {
		return
	}
	user := h.loginUser(w, r, body, "externalUsername")
	if user == "" || !h.allow(w, r, "offline-totp", user) {
		return
	}
	res, err := h.client.Offline.VerifyTotpFor(user, body.str("code"), h.actionType, h.ipOf(r), body.nonEmptyString("requestId"))
	if err != nil {
		sendRelayError(w, err)
		return
	}
	if !res.Approved || res.ExternalUsername == "" {
		status, out := offlineFailure(res, false)
		writeRelayJSON(w, status, out)
		return
	}
	if err := h.authenticated(w, r, AuthenticatedInfo{ExternalUsername: res.ExternalUsername, Via: ViaOfflineTotp}); err != nil {
		sendRelayError(w, err)
		return
	}
	writeRelayJSON(w, http.StatusOK, map[string]interface{}{"status": "success", "approved": true})
}

// ── Passkey: passwordless sign-in (identity is the typed email) ───────

func (h *relayHandler) passkeyPrimaryOptions(w http.ResponseWriter, r *http.Request, body relayBody) {
	email := strings.ToLower(body.str("email"))
	if !h.allow(w, r, "passkey-options", email) {
		return
	}
	res, err := h.client.WebAuthn.PrimaryOptions(email)
	if err != nil {
		sendRelayError(w, err)
		return
	}
	writeRelayJSON(w, http.StatusOK, res)
}

func (h *relayHandler) passkeyPrimaryVerify(w http.ResponseWriter, r *http.Request, body relayBody) {
	if !h.allow(w, r, "passkey-verify", "") {
		return
	}
	res, err := h.client.WebAuthn.PrimaryVerify(body.nonEmptyString("attemptId"), body.object("response"))
	if err != nil {
		sendRelayError(w, err)
		return
	}
	switch {
	case res.Success:
		if err := h.authenticated(w, r, AuthenticatedInfo{ExternalUsername: res.ExternalUsername, RequestID: res.RequestID, Via: ViaPasskey}); err != nil {
			sendRelayError(w, err)
			return
		}
		out := map[string]interface{}{"status": "success"}
		if res.RequestID != "" {
			out["requestId"] = res.RequestID
		}
		writeRelayJSON(w, http.StatusOK, out)
	case res.RequiresStepUp:
		writeRelayJSON(w, http.StatusOK, map[string]interface{}{"requiresStepUp": true})
	default:
		writeRelayJSON(w, http.StatusUnauthorized, map[string]interface{}{"error": "verification_failed"})
	}
}

// ── Passkey: approve an already-pending 2FA request (second factor; pair
//    with @touchque/web's passkeys.approveLogin({ requestId })) ─────────

func (h *relayHandler) passkeyApproveOptions(w http.ResponseWriter, r *http.Request, body relayBody) {
	if !h.allow(w, r, "passkey-approve", "") {
		return
	}
	res, err := h.client.WebAuthn.AuthenticateOptions(body.nonEmptyString("requestId"))
	if err != nil {
		sendRelayError(w, err)
		return
	}
	writeRelayJSON(w, http.StatusOK, res)
}

func (h *relayHandler) passkeyApproveVerify(w http.ResponseWriter, r *http.Request, body relayBody) {
	if !h.allow(w, r, "passkey-approve", "") {
		return
	}
	requestID := body.nonEmptyString("requestId")
	res, err := h.client.WebAuthn.AuthenticateVerify(requestID, body.object("response"))
	if err != nil {
		sendRelayError(w, err)
		return
	}
	// Open the session only for the user TouchQue says was approved. A name
	// sent by the browser is never trusted: anyone could approve their own
	// request and claim to be someone else.
	if res.Success && h.opts.LoginUser != nil && res.ExternalUsername != "" && !h.matchesLoginUser(r, res.ExternalUsername) {
		writeRelayJSON(w, http.StatusUnauthorized, map[string]interface{}{"error": "verification_failed"})
		return
	}
	if res.Success && res.ExternalUsername != "" {
		rid := res.RequestID
		if rid == "" {
			rid = requestID
		}
		if err := h.authenticated(w, r, AuthenticatedInfo{ExternalUsername: res.ExternalUsername, RequestID: rid, Via: ViaPasskey}); err != nil {
			sendRelayError(w, err)
			return
		}
	}
	writeRelayJSON(w, http.StatusOK, res)
}

// ── Passkey: enrollment / management (auth required) ─────────────────

// passkeyEnrollAction is the reserved action whose approval on the phone
// unlocks adding a passkey.
const passkeyEnrollAction = "PASSKEY_ENROLL"

// passkeyRegisterOptions: a user with a linked phone approves adding a
// passkey there first. A passkey approves requests on its own, so a stolen
// session of your app must not be able to add one. Same two-phase contract
// as /login: 202 with the step (and number to show) until approved, then
// the options.
func (h *relayHandler) passkeyRegisterOptions(w http.ResponseWriter, r *http.Request, _ relayBody) {
	userID := h.requireUserID(w, r)
	if userID == "" {
		return
	}
	token, offline, code, codeType := guardInputFromRequest(r)
	if token == "" {
		res, err := h.client.WebAuthn.RegisterOptions(userID, true)
		if err == nil {
			writeRelayJSON(w, http.StatusOK, res)
			return
		}
		apiErr, ok := err.(*APIError)
		if !ok || apiErr.StatusCode != http.StatusForbidden || apiErr.Code != "enrollment_approval_required" {
			sendRelayError(w, err)
			return
		}
	}
	in := GuardInput{
		User: userID, Action: passkeyEnrollAction, NoEnroll: true,
		IP: h.ipOf(r), UserAgent: r.UserAgent(),
		Token: token, Offline: offline == "1", Code: code, CodeType: codeType,
	}
	if isStatusPoll(h.client, in) {
		if !h.allowN(w, r, "login-poll", "", pollsPerAttempt) {
			return
		}
	} else if !h.allow(w, r, "passkey-enroll", userID) {
		return
	}
	result := runGuard(h.client, in)
	if result.Approved == nil {
		if result.Body.Touchque.RetryAfter > 0 {
			w.Header().Set("Retry-After", strconv.Itoa(result.Body.Touchque.RetryAfter))
		}
		w.Header().Set("Cache-Control", "no-store")
		writeRelayJSON(w, result.Status, result.Body)
		return
	}
	res, err := h.client.WebAuthn.RegisterOptionsWithApproval(userID, true, result.Approved.RequestID)
	if err != nil {
		sendRelayError(w, err)
		return
	}
	writeRelayJSON(w, http.StatusOK, res)
}

func (h *relayHandler) passkeyRegisterVerify(w http.ResponseWriter, r *http.Request, body relayBody) {
	userID := h.requireUserID(w, r)
	if userID == "" {
		return
	}
	res, err := h.client.WebAuthn.RegisterVerify(userID, body.object("response"), body.nonEmptyString("label"))
	if err != nil {
		sendRelayError(w, err)
		return
	}
	writeRelayJSON(w, http.StatusOK, res)
}

func (h *relayHandler) passkeyListCredentials(w http.ResponseWriter, r *http.Request) {
	userID := h.requireUserID(w, r)
	if userID == "" {
		return
	}
	creds, err := h.client.WebAuthn.ListCredentials(userID)
	if err != nil {
		sendRelayError(w, err)
		return
	}
	writeRelayJSON(w, http.StatusOK, map[string]interface{}{"credentials": creds})
}

func (h *relayHandler) passkeyDeleteCredential(w http.ResponseWriter, r *http.Request, _ relayBody) {
	userID := h.requireUserID(w, r)
	if userID == "" {
		return
	}
	res, err := h.client.WebAuthn.DeleteCredentialForUser(r.PathValue("id"), userID)
	if err != nil {
		sendRelayError(w, err)
		return
	}
	writeRelayJSON(w, http.StatusOK, res)
}
