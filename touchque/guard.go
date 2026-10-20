package touchque

import (
	"context"
	"log"
	"strings"
)

// Guard header names the browser sends back while it waits.
const (
	GuardTokenHeader    = "X-TouchQue-Token"
	GuardOfflineHeader  = "X-TouchQue-Offline"
	GuardCodeHeader     = "X-TouchQue-Code"
	GuardCodeTypeHeader = "X-TouchQue-Code-Type"
	// GuardBrowserHeader carries the browser's device-bound key proof
	// (silent sign-ins). Require and the relay read it only when their
	// SilentSignIn option is on.
	GuardBrowserHeader = "X-TouchQue-Browser"
)

// maxBrowserProof: a real proof is a few hundred characters; anything far
// larger is not one and is neither checked nor passed on.
const maxBrowserProof = 4096

var guardStatus = map[StepState]int{
	StepWaiting: 202, StepEnroll: 202, StepPasskeyRequired: 202, StepOffline: 202,
	StepApproved: 200, StepRejected: 403, StepBlocked: 403, StepExpired: 408, StepFrozen: 423, StepRateLimited: 429,
}

// GuardInput is what runGuard needs from the current request — the same
// shape http_middleware.go's Require builds from a *http.Request.
type GuardInput struct {
	User string
	// NoEnroll: never issue a first-time linking QR (and recovery codes) for a
	// user without a phone. Set it whenever User is not proven by your own
	// sign-in, e.g. a typed username before the password step: the QR would
	// let anyone link their own phone to that account.
	NoEnroll    bool
	Action      string
	Details     []LoginDetail
	ReferenceID string
	IP          string
	UserAgent   string
	Token       string
	Offline     bool
	Code        string
	CodeType    string
	// BrowserProof (silent sign-ins): the browser's device-bound key proof
	// (X-TouchQue-Browser), passed through untouched. Attached to the push,
	// so its approval makes the browser known.
	BrowserProof string
	// SilentSignIn (default off): a new attempt that carries BrowserProof
	// first asks TouchQue (Risk.Check); when it answers prompt: false the
	// guard approves at once, with no push (Assurance.Method "silent",
	// ConfirmedVia "SILENT", RequestID "silent", Reasons). Otherwise, and on
	// any error, the usual push starts.
	SilentSignIn bool
	// SilentSignInMaxAgeSeconds is your own limit on how long ago the last
	// phone approval in this browser may be (0 = always ask). nil leaves it
	// to TouchQue, which never goes beyond its own limit (7 days).
	SilentSignInMaxAgeSeconds *int
	// Context is for your TouchQue Actions only (event.context). Never shown on the phone.
	Context map[string]interface{}
}

// GuardError is the machine-readable error alongside a refusal's body.
type GuardError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

// GuardBody is the JSON sent to the browser for every response except a
// successful approval.
type GuardBody struct {
	Touchque Step        `json:"touchque"`
	Token    string      `json:"token,omitempty"`
	Error    *GuardError `json:"error,omitempty"`
}

// GuardResult is the outcome of one runGuard call: either Approved is set
// (run the protected action) or Body/Status describe what to send instead.
type GuardResult struct {
	Approved *Approval
	Status   int
	Body     *GuardBody
}

const tokenTTLMs = 10 * 60 * 1000

// isStatusPoll reports whether this request only polls an approval that is
// already on its way: a valid token bound to this user/action/details, still
// waiting, and no offline switch or typed code. It can only read the status,
// never start a push, so relays do not count it against the per-user push
// limit (with a 1.5 s poll the 6th poll was refused after 7.5 s).
func isStatusPoll(c *Client, in GuardInput) bool {
	if in.User == "" || in.Token == "" || in.Offline || in.Code != "" {
		return false
	}
	t := verifyGuardToken(c.apiSecret, in.Token)
	if t == nil || t.Rid == "" {
		return false
	}
	if t.U != in.User || t.A != in.Action || t.D != detailsDigest(in.Details) || t.R != in.ReferenceID {
		return false
	}
	return t.St == string(StepWaiting) || t.St == string(StepPasskeyRequired) || t.St == string(StepOffline)
}

// runGuard is the framework-agnostic step-up guard shared by every net/http
// adapter (see Require). Contract, the same in every TouchQue server SDK:
//
//	1st request            -> 202 {"touchque": step, "token": ...}   show the step in your UI
//	repeat with the token   -> 202 while waiting, then the protected action runs once
//	refused                 -> 403 / 408 / 423 / 429 {"touchque": {"state": ..., ...}}
func runGuard(c *Client, in GuardInput) GuardResult {
	return runGuardContext(context.Background(), c, in)
}

// runGuardContext is runGuard bound to ctx (the incoming request's): it
// cancels the silent sign-in check, which then falls back to the usual start.
func runGuardContext(ctx context.Context, c *Client, in GuardInput) GuardResult {
	if in.User == "" {
		return GuardResult{Status: 401, Body: &GuardBody{
			Touchque: Step{State: StepBlocked, Reason: "unauthenticated"},
			Error:    &GuardError{Code: "unauthenticated", Message: "Sign in first."},
		}}
	}

	norm := normalizeDetails(in.Details)
	base := guardClaims{U: in.User, A: in.Action, D: detailsDigest(in.Details), R: in.ReferenceID}

	issue := func(step Step, extra guardClaims) GuardResult {
		if len(norm) > 0 && step.Details == nil && step.State != StepBlocked {
			step.Details = norm
		}
		claims := base
		claims.St = string(step.State)
		claims.Rid = step.RequestID
		claims.N = step.Number
		claims.Cc = step.CaseCode
		if step.Offline != nil {
			claims.Oc = step.Offline.ChallengeID
		}
		if extra.N != "" {
			claims.N = extra.N
		}
		if extra.Oc != "" {
			claims.Oc = extra.Oc
		}
		if extra.Rid != "" {
			claims.Rid = extra.Rid
		}
		claims.Exp = nowMs() + tokenTTLMs
		return GuardResult{Status: guardStatus[step.State], Body: &GuardBody{Touchque: step, Token: signGuardToken(c.apiSecret, claims)}}
	}

	bound := verifyGuardToken(c.apiSecret, in.Token)
	if bound != nil && (bound.U != base.U || bound.A != base.A || bound.D != base.D || bound.R != base.R) {
		bound = nil
	}

	// Offline: the user typed the code from the phone.
	if bound != nil && in.Code != "" && (bound.St == string(StepOffline) || in.CodeType == "totp") {
		isTotp := in.CodeType == "totp"
		var res *OfflineVerifyResult
		var err error
		if isTotp {
			res, err = c.Offline.VerifyTotpFor(in.User, in.Code, in.Action, in.IP, bound.Rid)
		} else {
			res, err = c.Offline.Verify(bound.Oc, in.Code)
		}
		if err != nil {
			return errorResult(err)
		}
		forThis := (res.ExternalUsername == "" || strings.EqualFold(res.ExternalUsername, in.User)) && (res.Type == "" || res.Type == in.Action)
		if res.Approved && forThis {
			method := "offline_code"
			via := "OFFLINE_CODE"
			if isTotp {
				method, via = "offline_totp", "OFFLINE_TOTP"
			}
			reqID := bound.Oc
			if reqID == "" {
				reqID = "offline-totp"
			}
			return GuardResult{Status: 200, Approved: &Approval{
				RequestID: reqID, User: in.User, Action: in.Action,
				Assurance: &Assurance{PhishingResistant: false, Method: method}, ConfirmedVia: via,
			}}
		}
		if res.Reason == "invalid_code" && !isTotp {
			return issue(Step{State: StepOffline, Offline: &OfflineStep{ChallengeID: bound.Oc, AttemptsLeft: res.AttemptsLeft}}, guardClaims{Oc: bound.Oc, Rid: bound.Rid, N: bound.N})
		}
		if res.Reason == "invalid_code" {
			return issue(Step{State: StepOffline, Reason: "invalid_code"}, guardClaims{Oc: bound.Oc, Rid: bound.Rid, N: bound.N})
		}
		// The phone rejected the push this QR belongs to: the whole sign-in is over.
		if res.Reason == "request_rejected" {
			return issue(Step{State: StepRejected, RequestID: bound.Rid, Reason: "request_rejected"}, guardClaims{})
		}
		// The push now waits for a passkey (Vishing Shield): no code may finish it.
		if res.Reason == "passkey_required" && bound.Rid != "" {
			return issue(Step{State: StepPasskeyRequired, RequestID: bound.Rid, Number: bound.N}, guardClaims{N: bound.N})
		}
		state := StepBlocked
		if res.Reason == "expired" {
			state = StepExpired
		}
		reason := res.Reason
		if reason == "" {
			reason = "offline_failed"
		}
		return issue(Step{State: state, Reason: reason}, guardClaims{})
	}

	if in.Offline {
		// Link the QR to the push it follows: a phone-side rejection kills it, and a push that asked
		// for number matching makes the QR ask for the same number.
		rid := ""
		if bound != nil {
			rid = bound.Rid
		}
		ch, err := c.Offline.Challenge(OfflineChallengeOptions{
			ExternalUsername: in.User, Type: in.Action, Details: norm, ClientIP: in.IP, UserAgent: in.UserAgent, RequestID: rid,
		})
		if err != nil {
			if apiErr, ok := err.(*APIError); ok && apiErr.StatusCode == 409 && (apiErr.Code == "request_rejected" || dataError(apiErr) == "request_rejected") {
				return issue(Step{State: StepRejected, RequestID: rid, Reason: "request_rejected"}, guardClaims{})
			}
			// The push it would follow now waits for a passkey (Vishing Shield): no QR, run the passkey.
			if apiErr, ok := err.(*APIError); ok && rid != "" && (apiErr.Code == "passkey_required" || dataError(apiErr) == "passkey_required") {
				return issue(Step{State: StepPasskeyRequired, RequestID: rid, Number: bound.N}, guardClaims{N: bound.N})
			}
			if apiErr, ok := err.(*APIError); ok && apiErr.StatusCode < 500 {
				reason := apiErr.Code
				if reason == "" {
					reason = dataError(apiErr)
				}
				if reason == "" {
					reason = "offline_unavailable"
				}
				return issue(Step{State: StepBlocked, Reason: reason}, guardClaims{})
			}
			return errorResult(err)
		}
		n := ch.ChallengeCode
		if n == "" && bound != nil {
			n = bound.N
		}
		return issue(Step{State: StepOffline, Offline: &OfflineStep{
			ChallengeID: ch.ChallengeID, QRDataURL: ch.QRDataURL, ExpiresAt: ch.ExpiresAt, TotpAvailable: ch.TotpAvailable,
			ChallengeCode: ch.ChallengeCode,
		}}, guardClaims{Rid: rid, N: n})
	}

	// Waiting on a push / passkey — or showing the offline QR next to a push that is still open: poll, and run
	// the action once it is approved. While the QR is up a phone-side REJECT ends the attempt at once.
	if bound != nil && bound.Rid != "" && (bound.St == string(StepWaiting) || bound.St == string(StepPasskeyRequired) || bound.St == string(StepOffline)) {
		now, err := c.Check(bound.Rid)
		if err != nil {
			return errorResult(err)
		}
		if now.State == StepApproved {
			approval, cerr := c.Complete(bound.Rid, in.User, in.Action, CompleteExpect{Details: in.Details, ReferenceID: in.ReferenceID})
			if cerr != nil {
				if apiErr, ok := cerr.(*APIError); ok && apiErr.StatusCode == 409 {
					reason := apiErr.Code
					if reason == "" {
						reason = "already_used"
					}
					return issue(Step{State: StepExpired, Reason: reason}, guardClaims{})
				}
				return errorResult(cerr)
			}
			return GuardResult{Status: 200, Approved: approval}
		}
		// The push behind the QR was moved to a passkey after a tap during a call
		// (Vishing Shield): the QR's code would be refused now, so switch to the passkey.
		if bound.St == string(StepOffline) && now.State == StepPasskeyRequired {
			return issue(Step{State: StepPasskeyRequired, RequestID: bound.Rid, Number: bound.N}, guardClaims{N: bound.N})
		}
		if bound.St == string(StepOffline) && (now.State == StepWaiting || now.State == StepExpired) {
			// Still (or no longer) pending: nothing changed for the user — keep showing the QR they have.
			return issue(Step{State: StepOffline, Offline: &OfflineStep{ChallengeID: bound.Oc}}, guardClaims{Oc: bound.Oc, Rid: bound.Rid, N: bound.N})
		}
		if now.State == StepWaiting || now.State == StepPasskeyRequired {
			return issue(Step{State: now.State, RequestID: bound.Rid, Number: bound.N, CaseCode: bound.Cc}, guardClaims{N: bound.N})
		}
		return issue(Step{State: now.State, RequestID: bound.Rid}, guardClaims{})
	}

	// Anything else (no/foreign token, enrollment finished, new attempt): start.
	browserProof := ""
	if len(in.BrowserProof) <= maxBrowserProof {
		browserProof = in.BrowserProof
	}
	if in.SilentSignIn && browserProof != "" {
		if approval := silentApproval(ctx, c, in, browserProof); approval != nil {
			return GuardResult{Status: 200, Approved: approval}
		}
	}
	step, err := c.Start(in.Action, in.User, StartOptions{
		Details: norm, ReferenceID: in.ReferenceID, IP: in.IP, UserAgent: in.UserAgent, NoEnroll: in.NoEnroll,
		BrowserProof: browserProof, Context: in.Context,
	})
	if err != nil {
		return errorResult(err)
	}
	return issue(*step, guardClaims{})
}

// silentApproval asks TouchQue whether this known browser may sign in
// without the phone. It fails closed: only an answer of exactly
// prompt: false approves; any error (network, 4xx, 5xx, a server without
// silent sign-ins) returns nil, which means "ask as usual".
func silentApproval(ctx context.Context, c *Client, in GuardInput, browserProof string) *Approval {
	res, err := c.Risk.Check(ctx, RiskCheckOptions{
		ExternalUsername: in.User, Type: in.Action, ClientIP: in.IP, UserAgent: in.UserAgent,
		BrowserProof: browserProof, MaxAgeSeconds: in.SilentSignInMaxAgeSeconds, Context: in.Context,
	})
	if err != nil || res == nil || res.Prompt {
		return nil
	}
	return &Approval{
		RequestID: "silent", User: in.User, Action: in.Action,
		Assurance: &Assurance{PhishingResistant: false, Method: "silent"}, ConfirmedVia: "SILENT",
		Reasons: res.Reasons,
	}
}

// withSilentSignIn adds what an adapter passes for silent sign-ins: the
// X-TouchQue-Browser header, read only when the option is on.
func withSilentSignIn(in GuardInput, header func(string) string, on bool, maxAgeSeconds *int) GuardInput {
	if !on {
		return in
	}
	in.SilentSignIn = true
	in.SilentSignInMaxAgeSeconds = maxAgeSeconds
	in.BrowserProof = header(GuardBrowserHeader)
	return in
}

func errorResult(err error) GuardResult {
	if _, ok := err.(*ConfigError); ok {
		log.Printf("[TouchQue] %v", err)
		return GuardResult{Status: 500, Body: &GuardBody{
			Touchque: Step{State: StepBlocked, Reason: "misconfigured"},
			Error:    &GuardError{Code: "misconfigured", Message: "Two-factor approval is not configured correctly."},
		}}
	}
	log.Printf("[TouchQue] approval failed: %v", err)
	return GuardResult{Status: 503, Body: &GuardBody{
		Touchque: Step{State: StepBlocked, Reason: "unavailable"},
		Error:    &GuardError{Code: "unavailable", Message: "Two-factor approval is temporarily unavailable."},
	}}
}
