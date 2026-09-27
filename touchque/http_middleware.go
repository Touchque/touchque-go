package touchque

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"
)

// RequireOptions configures Require.
type RequireOptions struct {
	// User resolves who is approving from the request (required for the
	// login step — there is no signed-in user yet, return whoever just
	// passed your password check). If nil, User defaults to reading the
	// "X-Touchque-User" header (set your own auth middleware to add it, or
	// pass a real User func).
	User func(*http.Request) string
	// Details: what the phone shows and the approval is bound to. Build it
	// from server-side state.
	Details func(*http.Request) []LoginDetail
	// ReferenceID: your own transaction id, bound to the approval.
	ReferenceID func(*http.Request) string
	// IP: end user's address (default: r.RemoteAddr — set this explicitly
	// behind a reverse proxy, from your trusted X-Forwarded-For hop).
	IP func(*http.Request) string
}

type approvalContextKey struct{}

// ApprovalFromContext returns the approval Require stored on the request
// context, once the protected handler is running.
func ApprovalFromContext(ctx context.Context) (*Approval, bool) {
	a, ok := ctx.Value(approvalContextKey{}).(*Approval)
	return a, ok
}

func defaultUser(r *http.Request) string {
	return r.Header.Get("X-Touchque-User")
}

func defaultIP(r *http.Request) string {
	return r.RemoteAddr
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
		userOf = defaultUser
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

		result := runGuard(client, GuardInput{
			User: userOf(r), Action: action, Details: details, ReferenceID: referenceID,
			IP: ipOf(r), UserAgent: r.UserAgent(),
			Token: token, Offline: offline == "1", Code: code, CodeType: codeType,
		})

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
