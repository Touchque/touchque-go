package touchque

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"strconv"
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
	// device-bound key proof (X-TouchQue-Browser, added by @touchque/web with
	// browserKey: true) first asks TouchQue whether anything about it is new.
	// If nothing is, next runs at once with no push (the approval's
	// Assurance.Method is "silent", with Reasons). Otherwise, and on any
	// error, the usual push starts and its approval makes the browser known.
	SilentSignIn bool
	// SilentSignInMaxAgeSeconds is your own limit on how long ago the last
	// phone approval in that browser may be (0 = always ask). nil leaves it
	// to TouchQue, which never goes beyond its own limit (7 days).
	SilentSignInMaxAgeSeconds *int
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
// "X-TouchQue-Token: <token>". Once approved, next runs exactly once, with
// the approval available via ApprovalFromContext(r.Context()).
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
		result := runGuardContext(r.Context(), client, in)

		if result.Approved != nil {
			ctx := context.WithValue(r.Context(), approvalContextKey{}, result.Approved)
			next.ServeHTTP(w, r.WithContext(ctx))
			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		if result.Body.Touchque.RetryAfter > 0 {
			w.Header().Set("Retry-After", strconv.Itoa(result.Body.Touchque.RetryAfter))
		}
		w.WriteHeader(result.Status)
		_ = json.NewEncoder(w).Encode(result.Body)
	})
}
