package touchque

import (
	"log"
	"strings"
)

// Guard header names the browser sends back while it waits.
const (
	GuardTokenHeader    = "X-TouchQue-Token"
	GuardOfflineHeader  = "X-TouchQue-Offline"
	GuardCodeHeader     = "X-TouchQue-Code"
	GuardCodeTypeHeader = "X-TouchQue-Code-Type"
)

var guardStatus = map[StepState]int{
	StepWaiting: 202, StepEnroll: 202, StepPasskeyRequired: 202, StepOffline: 202,
	StepApproved: 200, StepRejected: 403, StepBlocked: 403, StepExpired: 408, StepFrozen: 423, StepRateLimited: 429,
}

// GuardInput is what runGuard needs from the current request — the same
// shape http_middleware.go's Require builds from a *http.Request.
type GuardInput struct {
	User        string
	Action      string
	Details     []LoginDetail
	ReferenceID string
	IP          string
	UserAgent   string
	Token       string
	Offline     bool
	Code        string
	CodeType    string
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

// runGuard is the framework-agnostic step-up guard shared by every net/http
// adapter (see Require). Contract, the same in every TouchQue server SDK:
//
//	1st request            -> 202 {"touchque": step, "token": ...}   show the step in your UI
//	repeat with the token   -> 202 while waiting, then the protected action runs once
//	refused                 -> 403 / 408 / 423 / 429 {"touchque": {"state": ..., ...}}
func runGuard(c *Client, in GuardInput) GuardResult {
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
		if step.Offline != nil {
			claims.Oc = step.Offline.ChallengeID
		}
		if extra.N != "" {
			claims.N = extra.N
		}
		if extra.Oc != "" {
			claims.Oc = extra.Oc
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
			res, err = c.Offline.VerifyTotp(in.User, in.Code, in.Action, in.IP)
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
			return issue(Step{State: StepOffline, Offline: &OfflineStep{ChallengeID: bound.Oc, AttemptsLeft: res.AttemptsLeft}}, guardClaims{Oc: bound.Oc})
		}
		if res.Reason == "invalid_code" {
			return issue(Step{State: StepOffline, Reason: "invalid_code"}, guardClaims{Oc: bound.Oc})
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
		ch, err := c.Offline.Challenge(OfflineChallengeOptions{
			ExternalUsername: in.User, Type: in.Action, Details: norm, ClientIP: in.IP, UserAgent: in.UserAgent,
		})
		if err != nil {
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
		return issue(Step{State: StepOffline, Offline: &OfflineStep{
			ChallengeID: ch.ChallengeID, QRDataURL: ch.QRDataURL, ExpiresAt: ch.ExpiresAt, TotpAvailable: ch.TotpAvailable,
		}}, guardClaims{})
	}

	// Waiting on a push / passkey: poll, and run the action once it is approved.
	if bound != nil && bound.Rid != "" && (bound.St == string(StepWaiting) || bound.St == string(StepPasskeyRequired)) {
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
		if now.State == StepWaiting || now.State == StepPasskeyRequired {
			return issue(Step{State: now.State, RequestID: bound.Rid, Number: bound.N}, guardClaims{N: bound.N})
		}
		return issue(Step{State: now.State, RequestID: bound.Rid}, guardClaims{})
	}

	// Anything else (no/foreign token, enrollment finished, new attempt): start.
	step, err := c.Start(in.Action, in.User, StartOptions{Details: norm, ReferenceID: in.ReferenceID, IP: in.IP, UserAgent: in.UserAgent})
	if err != nil {
		return errorResult(err)
	}
	return issue(*step, guardClaims{})
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
