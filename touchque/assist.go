package touchque

import (
	"context"
	"net/url"
)

// AssistResource is the help desk: IT working on a person's account in the
// open.
//
//  1. Before your help desk acts on someone's account: Open with the person
//     and the signed-in agent. The person's phone gets a calm notice ("<agent>
//     from IT is working on your account now"); while the session is open,
//     their "someone says they're from IT" button shows this agent, and with
//     none open it tells them to hang up (webhook ASSIST_CLAIM_UNVERIFIED).
//  2. Before a sensitive action (a factor or password reset, an activation or
//     recovery link, an unlock, a new phone, removing a passkey): Verify. Show
//     ChallengeCode to the agent only; they read it to the person, who types
//     it on their phone and approves with Face ID. Default deny.
//  3. Right before the action: Spend (a passed check, for that action, at most
//     ten minutes old, once). Unfreeze lifts a freeze the same way.
//
// No phone (Code "no_phone", Data["route"] "never_locked_out"): the person
// moves to a new phone with Never Locked Out (Recovery); the help desk cannot.
type AssistResource struct {
	http *httpClient
}

func newAssistResource(http *httpClient) *AssistResource {
	return &AssistResource{http: http}
}

// AssistAgent is the signed-in agent: Name (and Title) are shown on the
// person's phone; Ref is your id for them (default Name).
type AssistAgent struct {
	Ref   string `json:"ref,omitempty"`
	Name  string `json:"name"`
	Title string `json:"title,omitempty"`
}

// OpenAssistOptions starts helping a person.
type OpenAssistOptions struct {
	ExternalUsername string
	Agent            AssistAgent
	// Reason is a ticket or a few words, for the log.
	Reason string
	// TTLMinutes is 5–120; 0 means the default, 30.
	TTLMinutes int
	// NoNotice skips the calm notice on the person's phone.
	NoNotice bool
}

// AssistCheck is one check on the person's phone. Outcome: pending, verified,
// wrong_number, not_me, coached, declined or expired.
type AssistCheck struct {
	RequestID  string  `json:"requestId"`
	Action     string  `json:"action"`
	ActionText string  `json:"actionText"`
	Outcome    string  `json:"outcome"`
	CreatedAt  string  `json:"createdAt"`
	SpentAt    *string `json:"spentAt"`
	ExpiresAt  *string `json:"expiresAt"`
}

// AssistSession is IT working on a person's account: OPEN until ended,
// expired or replaced. Phone false: the person has no working Touchque phone
// to check on (Never Locked Out).
type AssistSession struct {
	ID               string        `json:"id"`
	ExternalUsername string        `json:"externalUsername"`
	Status           string        `json:"status"`
	Agent            AssistAgent   `json:"agent"`
	Reason           *string       `json:"reason"`
	Notified         bool          `json:"notified"`
	OpenedAt         string        `json:"openedAt"`
	ExpiresAt        string        `json:"expiresAt"`
	EndedAt          *string       `json:"endedAt"`
	EndedReason      *string       `json:"endedReason"`
	Phone            bool          `json:"phone"`
	Frozen           bool          `json:"frozen"`
	Checks           []AssistCheck `json:"checks"`
}

// CheckPassed reports whether the check of requestID passed on the person's
// phone and was not used yet.
func (s *AssistSession) CheckPassed(requestID string) bool {
	for _, c := range s.Checks {
		if c.RequestID == requestID {
			return c.Outcome == "verified" && c.SpentAt == nil
		}
	}
	return false
}

// VerifyAssistOptions asks the person's phone to confirm Action: reset_2fa,
// reset_password, activation_link, recovery_link, unlock, new_phone,
// remove_passkey, or your own (lowercase, digits, underscores). ActionText is
// shown on the phone: "IT (<agent>) is about to <ActionText>".
type VerifyAssistOptions struct {
	Action     string
	ActionText string
	Details    []map[string]string
}

// AssistCheckStarted carries the number to show the agent only.
type AssistCheckStarted struct {
	RequestID     string `json:"requestId"`
	ChallengeCode string `json:"challengeCode"`
	ExpiresAt     string `json:"expiresAt"`
	Action        string `json:"action"`
}

func assistPath(id, rest string) string { return "/assist/" + url.PathEscape(id) + rest }

func (ar *AssistResource) session(res interface{}, err error) (*AssistSession, error) {
	if err != nil {
		return nil, err
	}
	out := &AssistSession{}
	return out, remarshal(res, out)
}

// Open starts helping a person. A session of the same agent for the same
// person is replaced.
func (ar *AssistResource) Open(ctx context.Context, opts OpenAssistOptions) (*AssistSession, error) {
	if opts.ExternalUsername == "" || opts.Agent.Name == "" {
		return nil, &ConfigError{Message: "touchque: Assist.Open() needs ExternalUsername and Agent.Name"}
	}
	body := map[string]interface{}{"externalUsername": opts.ExternalUsername, "agent": opts.Agent}
	if opts.Reason != "" {
		body["reason"] = opts.Reason
	}
	if opts.TTLMinutes > 0 {
		body["ttlMinutes"] = opts.TTLMinutes
	}
	if opts.NoNotice {
		body["notify"] = false
	}
	return ar.session(ar.http.postCtx(ctx, "/assist", body))
}

// Get returns the session and its checks. Poll it while a check is pending.
func (ar *AssistResource) Get(ctx context.Context, id string) (*AssistSession, error) {
	if id == "" {
		return nil, &ConfigError{Message: "touchque: Assist.Get() needs the session id"}
	}
	return ar.session(ar.http.getWithQueryCtx(ctx, assistPath(id, ""), nil))
}

// List returns a person's sessions, or every open one (openOnly), newest first.
func (ar *AssistResource) List(ctx context.Context, externalUsername string, openOnly bool) ([]AssistSession, error) {
	if externalUsername == "" && !openOnly {
		return nil, &ConfigError{Message: "touchque: Assist.List() needs externalUsername or openOnly"}
	}
	params := map[string]string{}
	if externalUsername != "" {
		params["externalUsername"] = externalUsername
	}
	if openOnly {
		params["open"] = "true"
	}
	res, err := ar.http.getWithQueryCtx(ctx, "/assist", params)
	if err != nil {
		return nil, err
	}
	var out struct {
		Sessions []AssistSession `json:"sessions"`
	}
	if err := remarshal(res, &out); err != nil {
		return nil, err
	}
	if out.Sessions == nil {
		out.Sessions = []AssistSession{}
	}
	return out.Sessions, nil
}

// Verify asks the person's phone to confirm an action. An *APIError with Code
// no_phone (send them to Never Locked Out), assist_not_open or rate_limited
// says why not.
func (ar *AssistResource) Verify(ctx context.Context, id string, opts VerifyAssistOptions) (*AssistCheckStarted, error) {
	if id == "" || opts.Action == "" {
		return nil, &ConfigError{Message: "touchque: Assist.Verify() needs the session id and an action"}
	}
	body := map[string]interface{}{"action": opts.Action}
	if opts.ActionText != "" {
		body["actionText"] = opts.ActionText
	}
	if len(opts.Details) > 0 {
		body["details"] = opts.Details
	}
	res, err := ar.http.postCtx(ctx, assistPath(id, "/verify"), body)
	if err != nil {
		return nil, err
	}
	out := &AssistCheckStarted{}
	return out, remarshal(res, out)
}

// Spend uses a passed check for its action, right before you take it; an
// *APIError with Code check_required (428) otherwise.
func (ar *AssistResource) Spend(ctx context.Context, id, requestID, action string) (*AssistSession, error) {
	if id == "" || requestID == "" || action == "" {
		return nil, &ConfigError{Message: "touchque: Assist.Spend() needs the session id, requestID and action"}
	}
	return ar.session(ar.http.postCtx(ctx, assistPath(id, "/spend"), map[string]interface{}{"requestId": requestID, "action": action}))
}

// Unfreeze lifts the person's approval freeze with a passed check for unlock.
func (ar *AssistResource) Unfreeze(ctx context.Context, id, requestID string) (bool, *AssistSession, error) {
	if id == "" || requestID == "" {
		return false, nil, &ConfigError{Message: "touchque: Assist.Unfreeze() needs the session id and requestID"}
	}
	res, err := ar.http.postCtx(ctx, assistPath(id, "/unfreeze"), map[string]interface{}{"requestId": requestID})
	if err != nil {
		return false, nil, err
	}
	var out struct {
		Unfrozen bool          `json:"unfrozen"`
		Session  AssistSession `json:"session"`
	}
	if err := remarshal(res, &out); err != nil {
		return false, nil, err
	}
	return out.Unfrozen, &out.Session, nil
}

// End stops helping; checks still waiting on the phone expire.
func (ar *AssistResource) End(ctx context.Context, id, by, reason string) (*AssistSession, error) {
	if id == "" {
		return nil, &ConfigError{Message: "touchque: Assist.End() needs the session id"}
	}
	body := map[string]interface{}{}
	if by != "" {
		body["by"] = by
	}
	if reason != "" {
		body["reason"] = reason
	}
	return ar.session(ar.http.postCtx(ctx, assistPath(id, "/end"), body))
}
