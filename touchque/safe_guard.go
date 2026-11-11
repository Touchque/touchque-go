package touchque

import (
	"context"
	"net/url"
	"strconv"
	"time"
)

// SafeGuardResource is Safe Guard: a Safe transaction approved on the
// approver's phone for TouchqueSafeGuard (the guard on your Safe). You send
// the raw transaction; the phone gets the raw fields only, decodes them
// itself, shows its own rows and signs, with a key only its biometrics
// unlock, a 105-byte approval of the hash it computed. Touchque never holds a
// key that can approve.
//
//  1. Request asks the phone (same pipeline as Login.Request: risk engine,
//     push limit, Vishing Shield, case code, always biometrics).
//  2. WaitForApproval (or poll Status) until the phone answered.
//  3. Check SafeTx.Approval yourself with VerifySafeApproval: it needs your
//     own transaction and the approver's key from the guard, not this answer.
//  4. Purpose "approve": WithSafeApprovals(ownerSignatures, approvals) as the
//     signatures of execTransaction. "schedule": send SafeScheduleCall(safe,
//     governanceHash, approvals) to the guard; the change runs once its
//     waiting time is over.
type SafeGuardResource struct {
	http *httpClient
}

func newSafeGuardResource(h *httpClient) *SafeGuardResource { return &SafeGuardResource{http: h} }

// SafeGuardConfig is the guard's settings for this Safe, as you read them from
// chain. With RecipientLock on, a payment or allowance outside the address
// book is a governance change.
type SafeGuardConfig struct {
	Threshold     int  `json:"threshold"`
	GovThreshold  int  `json:"govThreshold"`
	GovDelay      int  `json:"govDelay"`
	ExitDelay     int  `json:"exitDelay"`
	RecipientLock bool `json:"recipientLock,omitempty"`
}

// SafeGuardRecipient is an entry of the guard's address book: the phone names
// the address with its label (at most 64 bytes, no control, bidi or invisible
// characters).
type SafeGuardRecipient struct {
	Address string `json:"address"`
	Label   string `json:"label,omitempty"`
}

// SafeGuardTx is the raw Safe transaction and what the phone needs to decode
// it like the guard. BatchTargets are the MultiSendCallOnly contracts the
// guard opens call by call (at most 5); ApproverIndex is this approver's index
// in the guard; Locale is the language of the rows on the phone ("tr" by
// default, or "en").
type SafeGuardTx struct {
	SafeTxTarget
	Config        SafeGuardConfig      `json:"config"`
	BatchTargets  []string             `json:"batchTargets,omitempty"`
	Recipients    []SafeGuardRecipient `json:"recipients,omitempty"`
	ApproverIndex int                  `json:"approverIndex"`
	Locale        string               `json:"locale,omitempty"`
}

// SafeGuardRequestOptions asks one approver's phone. Type is an action type
// from your dashboard; ExpiresIn is seconds, 30 to 300 (0 = 300).
type SafeGuardRequestOptions struct {
	ExternalUsername string
	Type             string
	SafeTx           SafeGuardTx
	ReferenceID      string
	ExpiresIn        int
	ClientIP         string
	UserAgent        string
}

// SafeGuardDecoded is Touchque's own decoding, for your logs and screens (the
// phone decodes for itself). Class: tighten, ordinary, governance or exit.
type SafeGuardDecoded struct {
	Class          string           `json:"class"`
	Flags          []string         `json:"flags"`
	SafeTxHash     string           `json:"safeTxHash"`
	GovernanceHash *string          `json:"governanceHash"`
	Rows           []SafeDisplayRow `json:"rows"`
}

// SafeGuardRequestResponse is a request on its way to the phone.
type SafeGuardRequestResponse struct {
	RequestID string           `json:"requestId"`
	Message   string           `json:"message"`
	ExpiresAt string           `json:"expiresAt"`
	CaseCode  string           `json:"caseCode,omitempty"`
	SafeTx    SafeGuardDecoded `json:"safeTx"`
}

// SafeGuardApproval is where an approval stands. Purpose "approve": append to
// the owners' signatures; "schedule": send guard.schedule. Approval (105
// bytes, 0x hex) and ExpiresAt (Unix seconds) are set once approved.
type SafeGuardApproval struct {
	Class          string   `json:"class"`
	Flags          []string `json:"flags"`
	SafeTxHash     string   `json:"safeTxHash"`
	GovernanceHash *string  `json:"governanceHash"`
	Purpose        string   `json:"purpose"`
	ApproverIndex  int      `json:"approverIndex"`
	Approval       string   `json:"approval,omitempty"`
	ExpiresAt      int64    `json:"expiresAt,omitempty"`
}

// SafeGuardStatus is a request's status. Provisional: given during a call or
// after a risky Second Thought answer; the person confirms it again later.
type SafeGuardStatus struct {
	RequestID        string             `json:"requestId"`
	ExternalUsername string             `json:"externalUsername"`
	Status           string             `json:"status"`
	Provisional      bool               `json:"provisional"`
	SafeTx           *SafeGuardApproval `json:"safeTx"`
}

// Request asks the approver's phone to approve a Safe transaction.
func (r *SafeGuardResource) Request(ctx context.Context, opts SafeGuardRequestOptions) (*SafeGuardRequestResponse, error) {
	if opts.ExternalUsername == "" {
		return nil, &ConfigError{Message: "touchque: SafeGuard.Request() needs ExternalUsername"}
	}
	if opts.Type == "" {
		return nil, &ConfigError{Message: "touchque: SafeGuard.Request() needs Type: an action type from your dashboard"}
	}
	body := map[string]interface{}{"externalUsername": opts.ExternalUsername, "type": opts.Type, "safeTx": opts.SafeTx}
	for k, v := range map[string]string{"referenceId": opts.ReferenceID, "clientIp": opts.ClientIP, "userAgent": opts.UserAgent} {
		if v != "" {
			body[k] = v
		}
	}
	if opts.ExpiresIn != 0 {
		body["expiresIn"] = opts.ExpiresIn
	}
	res, err := r.http.postCtx(ctx, "/safe-guard/approvals", body)
	if err != nil {
		return nil, err
	}
	out := &SafeGuardRequestResponse{}
	return out, remarshal(res, out)
}

// Status is the request's status and, once approved, the approval.
func (r *SafeGuardResource) Status(ctx context.Context, requestID string) (*SafeGuardStatus, error) {
	if requestID == "" {
		return nil, &ConfigError{Message: "touchque: SafeGuard.Status() needs a request ID"}
	}
	res, err := r.http.getWithQueryCtx(ctx, "/safe-guard/approvals/"+url.PathEscape(requestID), nil)
	if err != nil {
		return nil, err
	}
	out := &SafeGuardStatus{}
	return out, remarshal(res, out)
}

// WaitForApproval polls until the phone approved and returns the status with
// the approval: a *RejectedError when the person said no, a *TimeoutError
// when it expired or timeout (0 = 5 minutes, the request's own life) ran out.
// pollInterval 0 is 1.5 seconds.
func (r *SafeGuardResource) WaitForApproval(ctx context.Context, requestID string, timeout, pollInterval time.Duration) (*SafeGuardStatus, error) {
	if timeout == 0 {
		timeout = 5 * time.Minute
	}
	if pollInterval == 0 {
		pollInterval = 1500 * time.Millisecond
	}
	start := time.Now()
	for {
		status, err := r.Status(ctx, requestID)
		if err != nil {
			return nil, err
		}
		switch status.Status {
		case "CONFIRMED":
			return status, nil
		case "REJECTED":
			return nil, &RejectedError{Message: "Request " + requestID + " was rejected by the user."}
		case "EXPIRED":
			return nil, &TimeoutError{Message: "Request " + requestID + " expired before it was approved."}
		}
		if time.Since(start) > timeout {
			return nil, &TimeoutError{Message: "Safe Guard approval timed out after " + strconv.FormatInt(timeout.Milliseconds(), 10) + "ms"}
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(pollInterval):
		}
	}
}
