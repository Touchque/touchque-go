package touchque

import (
	"context"
	"encoding/json"
	"log/slog"
	"net"
	"net/http"
	"os"
	"strconv"
	"sync"
	"sync/atomic"
)

// RequireOptions configures Require.
type RequireOptions struct {
	// User resolves who is approving from YOUR server-side state: the
	// signed-in session, or — for the login step — whoever just passed your
	// password check. Required: Require panics when it is nil. Never read it
	// from anything the client sends (a header, a form field): the client
	// could then name any user and trigger their approval.
	User func(*http.Request) string
	// Details: what the phone shows and the approval is bound to. Build it
	// from server-side state.
	Details func(*http.Request) []LoginDetail
	// ReferenceID: your own transaction id, bound to the approval.
	ReferenceID func(*http.Request) string
	// IP: end user's address (default: the host part of r.RemoteAddr — set
	// this explicitly behind a reverse proxy, from your trusted
	// X-Forwarded-For hop; never the leftmost hop, which the client controls).
	IP func(*http.Request) string
	// SilentSignIn (default off): a new attempt whose browser sent its
	// device-bound key proof (X-Touchque-Browser, added by @touchque/web with
	// browserKey: true) first asks Touchque whether anything about it is new.
	// If nothing is, next runs at once with no push (the approval's
	// Assurance.Method is "silent", with Reasons). Otherwise, and on any
	// error, the usual push starts and its approval makes the browser known.
	SilentSignIn bool
	// SilentSignInMaxAgeSeconds is your own limit on how long ago the last
	// phone approval in that browser may be (0 = always ask). nil leaves it
	// to Touchque, which never goes beyond its own limit (7 days).
	SilentSignInMaxAgeSeconds *int
	// Context is for your Touchque Actions only (event.context): roles,
	// plan, amount… Never shown on the phone.
	Context func(*http.Request) map[string]interface{}
	// ErrorBody: your app's own error shape for the refusals Require sends
	// (401, 403, 408, 423, 429, 500, 503), e.g.
	//
	//	ErrorBody: func(r touchque.GuardRefusal) any {
	//	    return map[string]string{"message": r.Message, "code": r.Code}
	//	}
	//
	// A value that encodes to a JSON object is sent with "touchque" set to
	// the step (so @touchque/web still sees the state; no token is added),
	// anything else (a string, a number, a slice, nil) as it is. Status and
	// headers stay, and every refusal carries X-Touchque-State (and
	// X-Touchque-Reason). A panic, or a value that does not encode, sends the
	// default body and is logged. Never called for a 202 step or an approval.
	ErrorBody func(GuardRefusal) any
	// Logger receives Require's own lines (TQ_API_KEY / TQ_API_SECRET not set,
	// once per process; an ErrorBody that failed) and, with a nil client, the
	// lines of the client Require builds. nil: the client's Config.Logger;
	// with a nil client, nothing is logged.
	Logger *slog.Logger
}

// GuardRefusal is what RequireOptions.ErrorBody gets for an answer with
// status 400 or above.
type GuardRefusal struct {
	// Status is what Require sends: 401, 403, 408, 423, 429, 500 or 503.
	Status int `json:"status"`
	// Code is the guard's error code when it set one (unauthenticated,
	// misconfigured, unavailable), else the step's Reason, else its State.
	Code string `json:"code"`
	// Message is the guard's error message when it set one, else "The
	// approval was rejected.", "The approval expired. Try again.", "Too many
	// rejected approvals. Try again later.", "Too many attempts. Try again
	// later." or "The approval was refused.", by state.
	Message string `json:"message"`
	// Touchque is a copy of the step as it would be sent.
	Touchque Step `json:"touchque"`
}

var refusalMessages = map[StepState]string{
	StepRejected:    "The approval was rejected.",
	StepExpired:     "The approval expired. Try again.",
	StepFrozen:      "Too many rejected approvals. Try again later.",
	StepRateLimited: "Too many attempts. Try again later.",
}

// copyStep is a deep copy of s (its slices and pointers too), for code that
// must not change the step that is sent.
func copyStep(s Step) Step {
	raw, err := json.Marshal(s)
	if err != nil {
		return s
	}
	var out Step
	if json.Unmarshal(raw, &out) != nil {
		return s
	}
	return out
}

// setGuardHeaders sets the headers of a result that is not an approval:
// Cache-Control: no-store, Retry-After when the step has RetryAfter (423,
// 429), and on a refusal (status >= 400) X-Touchque-State and
// X-Touchque-Reason (when the step has a reason). @touchque/web builds the
// step from them when the body has no "touchque" (an ErrorBody that is not
// an object).
func setGuardHeaders(h http.Header, result GuardResult) {
	h.Set("Content-Type", "application/json")
	h.Set("Cache-Control", "no-store")
	if result.Body == nil {
		return
	}
	step := result.Body.Touchque
	if step.RetryAfter > 0 {
		h.Set("Retry-After", strconv.Itoa(step.RetryAfter))
	}
	if result.Status >= 400 {
		if step.State != "" {
			h.Set("X-Touchque-State", string(step.State))
		}
		if step.Reason != "" {
			h.Set("X-Touchque-Reason", step.Reason)
		}
	}
}

func guardRefusal(result GuardResult) GuardRefusal {
	step := result.Body.Touchque
	ref := GuardRefusal{Status: result.Status, Touchque: copyStep(step)}
	if result.Body.Error != nil {
		ref.Code, ref.Message = result.Body.Error.Code, result.Body.Error.Message
	}
	if ref.Code == "" {
		ref.Code = step.Reason
	}
	if ref.Code == "" {
		ref.Code = string(step.State)
	}
	if ref.Message == "" {
		ref.Message = refusalMessages[step.State]
	}
	if ref.Message == "" {
		ref.Message = "The approval was refused."
	}
	return ref
}

// responseBody is what Require sends for a result that is not an approval:
// result.Body, or for a refusal what errorBody makes of it.
func responseBody(result GuardResult, errorBody func(GuardRefusal) any, logger *slog.Logger) (body any) {
	if errorBody == nil || result.Status < 400 {
		return result.Body
	}
	defer func() {
		if r := recover(); r != nil {
			sdkLog(logger, slog.LevelError, "[Touchque] ErrorBody failed", "error", errorText(r))
			body = result.Body
		}
	}()
	custom, err := json.Marshal(errorBody(guardRefusal(result)))
	if err != nil {
		sdkLog(logger, slog.LevelError, "[Touchque] ErrorBody failed", "error", errorText(err))
		return result.Body
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(custom, &fields) != nil || fields == nil {
		return json.RawMessage(custom) // not an object: sent as it is
	}
	step, err := json.Marshal(result.Body.Touchque)
	if err != nil {
		return result.Body
	}
	fields["touchque"] = step
	return fields
}

// envClient is the client Require(nil, …) builds from TQ_API_KEY /
// TQ_API_SECRET / TQ_API_URL on first use and keeps once built; until then
// every request tries again.
type envClient struct {
	mu     sync.Mutex
	client atomic.Pointer[Client]
	logger *slog.Logger
}

// warnedUnconfigured: the missing keys are logged once per process.
var warnedUnconfigured atomic.Bool

func (e *envClient) get() *Client {
	if c := e.client.Load(); c != nil {
		return c
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if c := e.client.Load(); c != nil {
		return c
	}
	c, err := New()
	if err != nil {
		if e.logger != nil && warnedUnconfigured.CompareAndSwap(false, true) {
			if os.Getenv("TQ_API_KEY") == "" || os.Getenv("TQ_API_SECRET") == "" {
				sdkLog(e.logger, slog.LevelError, "[Touchque] TQ_API_KEY and TQ_API_SECRET are not set: routes guarded by Touchque answer 500 misconfigured.")
			} else {
				sdkLog(e.logger, slog.LevelError, "[Touchque] misconfigured", "error", errorText(err))
			}
		}
		return nil
	}
	if e.logger != nil {
		c.logger = e.logger
	}
	e.client.Store(c)
	return c
}

type approvalContextKey struct{}

// ApprovalFromContext returns the approval Require stored on the request
// context, once the protected handler is running.
func ApprovalFromContext(ctx context.Context) (*Approval, bool) {
	a, ok := ctx.Value(approvalContextKey{}).(*Approval)
	return a, ok
}

// defaultIP is the host part of r.RemoteAddr: "ip:port" is not an address,
// and the API would score your server instead of the user.
func defaultIP(r *http.Request) string {
	return hostOnly(r.RemoteAddr)
}

// hostOnly drops the port from "host:port" / "[v6]:port"; any other value
// is returned unchanged.
func hostOnly(addr string) string {
	if host, _, err := net.SplitHostPort(addr); err == nil {
		return host
	}
	return addr
}

func guardInputFromRequest(r *http.Request) (token, offline, code, codeType string) {
	token = r.Header.Get(GuardTokenHeader)
	off := r.Header.Get(GuardOfflineHeader)
	offlineBool := off == "1" || off == "true"
	code = r.Header.Get(GuardCodeHeader)
	codeType = r.Header.Get(GuardCodeTypeHeader)
	if offlineBool {
		offline = "1"
	}
	return
}

// Require wraps next with a one-line step-up guard:
//
//	mux.Handle("/transfer", touchque.Require(client, "SEND_MONEY", transferHandler, touchque.RequireOptions{
//	    User: func(r *http.Request) string { return sessionUser(r) },
//	    Details: func(r *http.Request) []touchque.LoginDetail {
//	        return []touchque.LoginDetail{{Label: "Amount", Value: r.FormValue("amount") + " EUR"}}
//	    },
//	}))
//
// Until the user approves on their phone this answers
// 202 {"touchque": step, "token": "..."}. Your page shows the step in its own
// design and sends the same request again with header
// "X-Touchque-Token: <token>". Once approved, next runs exactly once, with
// the approval available via ApprovalFromContext(r.Context()).
//
// A nil client is built from TQ_API_KEY / TQ_API_SECRET on the first request
// (New) and kept once built. While it cannot be built, Require answers 500
// misconfigured (401 when nobody is signed in) and next never runs; it never
// panics for it. Require panics only without RequireOptions.User.
func Require(client *Client, action string, next http.Handler, opts RequireOptions) http.Handler {
	userOf := opts.User
	if userOf == nil {
		// Fail at wiring time, not per request: there is no safe default.
		// (Before 3.1.1 this fell back to a client-supplied header.)
		panic("touchque.Require: RequireOptions.User is required — resolve the user from your server-side session")
	}
	ipOf := opts.IP
	if ipOf == nil {
		ipOf = defaultIP
	}
	var env *envClient
	if client == nil {
		env = &envClient{logger: opts.Logger}
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var details []LoginDetail
		if opts.Details != nil {
			details = opts.Details(r)
		}
		var referenceID string
		if opts.ReferenceID != nil {
			referenceID = opts.ReferenceID(r)
		}
		token, offline, code, codeType := guardInputFromRequest(r)

		in := withSilentSignIn(GuardInput{
			User: userOf(r), Action: action, Details: details, ReferenceID: referenceID,
			IP: ipOf(r), UserAgent: r.UserAgent(),
			Token: token, Offline: offline == "1", Code: code, CodeType: codeType,
		}, r.Header.Get, opts.SilentSignIn, opts.SilentSignInMaxAgeSeconds)
		if opts.Context != nil {
			in.Context = opts.Context(r)
		}
		c := client
		if env != nil {
			c = env.get() // nil while TQ_API_KEY / TQ_API_SECRET are not set: 500 misconfigured
		}
		result := runGuardContext(r.Context(), c, in)

		if result.Approved != nil {
			ctx := context.WithValue(r.Context(), approvalContextKey{}, result.Approved)
			next.ServeHTTP(w, r.WithContext(ctx))
			return
		}

		logger := opts.Logger
		if logger == nil && c != nil {
			logger = c.logger
		}
		body := responseBody(result, opts.ErrorBody, logger)
		setGuardHeaders(w.Header(), result)
		w.WriteHeader(result.Status)
		_ = json.NewEncoder(w).Encode(body)
	})
}
