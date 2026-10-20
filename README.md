# touchque-go

The official Go server SDK for [TouchQue](https://touchque.com) — biometric push
2FA, passkeys, and offline approval codes, added to any `net/http` backend
with one middleware wrap per route.

[![Go Reference](https://pkg.go.dev/badge/github.com/Touchque/touchque-go/v4.svg)](https://pkg.go.dev/github.com/Touchque/touchque-go/v4)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

📘 Full docs: **[authenticator.touchque.com/docs](https://authenticator.touchque.com/docs)**

## Install

```bash
go get github.com/Touchque/touchque-go/v4
```

## Setup

Get an API key and secret from your [TouchQue Dashboard](https://authenticator.touchque.com):

```bash
export TQ_API_KEY=tq_auth_your_key
export TQ_API_SECRET=your_api_secret
```

`touchque.NewClient(&touchque.Config{})` reads these from the environment when
left empty.

## Quick start (net/http)

```go
import "github.com/Touchque/touchque-go/v4/touchque"

tq := touchque.NewClient(&touchque.Config{})

mux.Handle("/transfer", touchque.Require(tq, "SEND_MONEY", transferHandler, touchque.RequireOptions{
    User: func(r *http.Request) string { return sessionUser(r) },
    Details: func(r *http.Request) []touchque.LoginDetail {
        return []touchque.LoginDetail{{Label: "Amount", Value: amountFromRequest(r)}}
    },
}))

func transferHandler(w http.ResponseWriter, r *http.Request) {
    approval, _ := touchque.ApprovalFromContext(r.Context())
    // only reached once the user approved on their phone
}
```

The risk checks (Tor, location, impossible travel) and the location shown on
the phone use the end user's address. `Require` sends the host part of
`r.RemoteAddr`; behind a reverse proxy that is the proxy, so set
`RequireOptions.IP` to the address your proxy saw (the rightmost
`X-Forwarded-For` hop it appended, never the leftmost one: the client
controls that).

Until the user approves on their phone, `Require` answers
**`202 {"touchque": step, "token": "..."}`** instead of calling `next`. Your
frontend renders `step` in its own UI (a matching number, or a QR code the
first time the user links the app) and sends the same request again with
header `X-TouchQue-Token: <token>` — see
[`@touchque/web`](https://www.npmjs.com/package/@touchque/web), which does
this loop for you in the browser. Once approved, the retried request reaches
`next` exactly once.

## Relay handler (every route a frontend needs)

`NewRelayHandler` serves the relay routes `@touchque/web` calls — `POST /login`,
enrollment, offline codes, passkey ceremonies and passkey management — so you
don't hand-write them. Mount it under a prefix with `http.StripPrefix`:

```go
mux.Handle("/touchque/", http.StripPrefix("/touchque", touchque.NewRelayHandler(tq, touchque.RelayOptions{
    UserID: func(r *http.Request) string { return sessionUser(r) },
    // The user who already passed your password step. Binds POST /login and the
    // offline routes to them; the offline routes stay off (403) without it.
    LoginUser: func(r *http.Request) string { return passwordVerifiedUser(r) },
    OnAuthenticated: func(w http.ResponseWriter, r *http.Request, info touchque.AuthenticatedInfo) error {
        return startSession(w, info.ExternalUsername) // set cookies here; the handler writes the body
    },
})))
```

| Route | Notes |
| --- | --- |
| `POST /enroll/start`, `GET /enroll/status` | signed-in user only; never replaces an already linked phone (409 `already_linked`) |
| `POST /login` | same two-phase contract as `Require`: `202 {"touchque": step, "token"}` until approved; with `SilentSignIn`, a known browser is approved at once (see Silent sign-ins) |
| `POST /offline/challenge`, `/offline/verify`, `/offline/totp` | off (403 `OFFLINE_REQUIRES_FIRST_FACTOR`) unless `LoginUser` or `AllowOfflineWithoutFirstFactor` is set |
| `POST /passkey/authenticate/options`, `/passkey/authenticate/verify` | passwordless sign-in (no `email`: any passkey of your site, for passkey autofill) |
| `POST /passkey/login/options`, `/passkey/login/verify` | approve a pending sign-in with a passkey |
| `POST /passkey/register/options`, `/passkey/register/verify`, `GET /passkey/credentials`, `DELETE /passkey/credentials/{id}` | signed-in user only |

- `UserID` is required (`NewRelayHandler` panics without it). Signed-in-only
  routes answer 401 `UNAUTHORIZED_FOR_2FA` when it returns `""`.
- With `LoginUser`, usernames in the request body are ignored (401
  `FIRST_FACTOR_REQUIRED` when it returns `""`), and `/offline/verify` and
  `/passkey/login/verify` only open a session for the user TouchQue reports if
  it matches. `OnAuthenticated` always receives TouchQue's user, never one from
  the body.
- Pre-auth routes are rate limited in memory, per route: 20 requests per IP and
  5 per username per minute (429 `RATE_LIMITED` + `Retry-After`). Tune with
  `RateLimit: &touchque.RateLimitOptions{...}`, or set `Disabled: true` if you
  limit in front. Set `IP` behind a reverse proxy (default: the host of
  `r.RemoteAddr`).
- TouchQue client errors are forwarded with their machine-readable code only;
  5xx and network failures become 502 `relay_error`. JSON bodies are read only
  with `Content-Type: application/json`, up to 100 KiB.

## The three primitives, if you're not using `Require`

```go
step, _ := tq.Start(ctx, "SEND_MONEY", touchque.StartOptions{
    User:    "jane@acme.com",
    Details: []touchque.LoginDetail{{Label: "Amount", Value: "250 EUR"}},
})
// step.State: touchque.StepWaiting (show step.Number) | touchque.StepEnroll (show step.Enroll.QRCodeDataURL)
//             | StepApproved | StepRejected | StepExpired | StepPasskeyRequired | StepFrozen | StepBlocked

latest, _ := tq.Check(ctx, step.RequestID)

// Once approved, consume it exactly once, right before doing the protected thing:
approval, err := tq.Complete(ctx, step.RequestID, touchque.CompleteExpectations{
    User: "jane@acme.com", Action: "SEND_MONEY",
    Details: []touchque.LoginDetail{{Label: "Amount", Value: "250 EUR"}},
})
```

`Complete` verifies the approval was actually issued for this user, action
and transaction, and can only be consumed once.

## Passkeys (phishing-resistant)

Push approval and offline codes stop password reuse and push fatigue, but a
real-time phishing proxy can still relay them. A passkey can't be phished —
the browser signs your site's real origin, and TouchQue refuses any other
(NIST SP 800-63B-4 §3.2.5). Register one via `tq.WebAuthn` on the server and
`@touchque/web`'s `passkeys.register()` in the browser; optionally require it
for critical actions in the Dashboard's Security Policy.

## Offline sign

```go
ch, _ := tq.Offline.Challenge(touchque.OfflineChallengeOptions{
    ExternalUsername: "jane@acme.com", Type: "WITHDRAW",
    Details: []touchque.LoginDetail{{Label: "Amount", Value: "1,250.00 USD"}},
})
// show ch.QRDataURL — the phone scans it offline and shows a 7-character code
result, _ := tq.Offline.Verify(ch.ChallengeID, code)
```

**A QR that follows a push.** Set `RequestID` when the offline QR is the fallback for a push the user
already started (the guard does this for you):

```go
ch, _ := tq.Offline.Challenge(touchque.OfflineChallengeOptions{ExternalUsername: "jane@acme.com", Type: "LOGIN", RequestID: step.RequestID})
// ch.ChallengeCode is the number to print under the QR when number matching applies.
```

If the user **rejects the push on the phone, the offline QR dies with it**: no new QR is issued for that
sign-in (409 `request_rejected`), a code for a QR already on screen is refused (`Reason == "request_rejected"`)
and so is the time-based code (`VerifyTotpFor(..., requestID)`). With number matching, print `ChallengeCode`
under the QR: the phone shows it among two decoys and the user taps the match; a wrong tap yields a code that
fails verification.

## Webhooks

```go
event, err := tq.Webhook.Verify(rawBody, r.Header.Get("X-Signature"))
if err != nil {
    w.WriteHeader(http.StatusForbidden) // not from TouchQue
    return
}
if event["event"] == touchque.EventApprovalRevoked {
    endSessionsBuiltOn(event["requestId"])
}
```

Login results carry `status` (`SUCCESS` | `REJECTED`) and, when rejected, a `reason` (`touchque.Reason*`):
`user_rejected`, `user_reported_fraud`, `user_reported_coached` (the user said someone on the phone told
them to approve), `risk_reversed`, `risk_step_up`, `approval_signature_invalid`, `device_integrity_failed`,
`vishing_suspected` and `phishing_origin` (see Vishing Shield). Treat a reason you do not know as a rejection.
Event webhooks carry `event` (`touchque.Event*`): `DEVICE_LINKED`, `DEVICE_UNLINKED`, `PASSKEY_REGISTERED`,
`PASSKEY_DELETED`, `APPROVAL_RECONFIRMED`, `APPROVAL_REVOKED`. Ignore events you do not know.

## Vishing Shield (someone on the phone guiding the user)

The phone tells TouchQue, signed with its hardware key, whether a call was active (or just ended), the screen
was shared or the phone remote-controlled when the user tapped Approve. Depending on the server's mode:

- **Passkey instead.** A user with a passkey finishes in the browser: the request stays open and turns into
  `passkey_required` mid-flight. The step-up flow and the relay handle it; the blocking `Login.VerifyWithOptions` returns
  `*touchque.PasskeyRequiredError` (`Reason == "step_up"`). No offline or recovery code can finish such a request.
- **Refused.** A critical action without a passkey is rejected (`reason: vishing_suspected`).
- **Provisional.** Anything else is approved with `Provisional` set on `Approval` from `Complete`. Let the user
  in, but treat the session as limited: TouchQue refuses the user's critical actions (`blocked` / `provisional`)
  until the phone re-confirms after the call (`APPROVAL_RECONFIRMED`). `APPROVAL_REVOKED` (`reason` `COACHED` or
  `UNDO`) means end the session; an approval revoked before you consumed it can no longer be consumed
  (409 `revoked`).

**Mirror Alarm.** The first waiting step carries `canary.url`. `@touchque/web` loads it on the page showing the
sign-in and sends a beacon to it, so a real-time phishing proxy in front of your site shows up as itself: the
approval is refused (`reason: phishing_origin`) and the phone warns the user. Allow the canary host in your
Content-Security-Policy (`img-src` and `connect-src`).

## TouchQue Actions (your code in the approval pipeline)

Alerts, step-ups and refusals by country, local time, role or amount, passkeys
for admins — from a template or a few lines of JavaScript, replayed against your
real recent sign-ins before they go live. Full guide: [ACTIONS.md](../ACTIONS.md).

```go
client.Actions.Deploy("night-alert", touchque.DeployActionOptions{Trigger: "approval.decided",
	Template: &touchque.ActionTemplateRef{ID: "alert", Params: map[string]interface{}{"channel": "slack",
		"when": map[string]interface{}{"countries": []string{"TR"}, "hours": map[string]interface{}{"from": 0, "to": 6}}}}})

draft := `exports.onExecute = async (event, api) => { if (event.context?.amount > 10000) api.stepUp("Over 10,000"); };`
report, _ := client.Actions.DryRun(touchque.DryRunActionOptions{ActionDraft: touchque.ActionDraft{Trigger: "login.request", Code: draft}})
_ = report.Transitions // map["push→number_match"]3
client.Actions.Deploy("big-transfers", touchque.DeployActionOptions{Trigger: "login.request", Code: draft})
```

Give Actions what only your server knows with `RequireOptions.Context` (never
shown on the phone). Loosening calls need a capability an admin approves on
their phone. Action types moved to `client.ActionTypes` in v4.

## Silent sign-ins (stop asking when nothing is new)

A user who approved on their phone in this browser a little while ago, from the same phone, network and country,
with no risk signal since, does not need another push. TouchQue's risk engine decides; your server only skips the
push when it says so.

1. In the browser, `@touchque/web` 1.4.0 with `createTouchQueWeb({ browserKey: true })` keeps a non-extractable
   key for your site and sends a fresh, signed proof of it in the `X-TouchQue-Browser` header
   (`touchque.GuardBrowserHeader`).
2. On the server, turn on `SilentSignIn`:

```go
mux.Handle("/login/2fa", touchque.Require(tq, "LOGIN", signInHandler, touchque.RequireOptions{
    User:         func(r *http.Request) string { return passwordVerifiedUser(r) },
    SilentSignIn: true,
}))

func signInHandler(w http.ResponseWriter, r *http.Request) {
    approval, _ := touchque.ApprovalFromContext(r.Context())
    // approval.Assurance.Method is "silent" when no push was needed; approval.Reasons say why.
}

mux.Handle("/touchque/", http.StripPrefix("/touchque", touchque.NewRelayHandler(tq, touchque.RelayOptions{
    UserID:       func(r *http.Request) string { return sessionUser(r) },
    LoginUser:    func(r *http.Request) string { return passwordVerifiedUser(r) },
    SilentSignIn: true, // SilentSignInMaxAgeSeconds sets your own limit
})))
```

With it on, a new attempt that carries the header first calls `tq.Risk.Check`. Only an answer of exactly
`prompt: false` approves it at once, with nothing sent to the phone: the `Approval` has
`Assurance{Method: "silent", PhishingResistant: false}`, `ConfirmedVia: "SILENT"`, `RequestID: "silent"` and
`Reasons` (`known_browser`, `recent_approval`, `same_phone`, `familiar_network`, `no_risk_signal`); the relay calls
`OnAuthenticated` with `Via: touchque.ViaSilent`. Anything else, and any error in the check, starts the usual push
with the proof attached, so its approval makes the browser known. Polling with the token never checks again.
`SilentSignInMaxAgeSeconds` (`*int`, seconds; `0` = always ask) sets your own limit on how long ago the last phone
approval in that browser may be.

TouchQue only lets a sign-in through silently when all of this holds: the browser proved its key and was approved
on the phone (a confirmed push, not one approved during a call, or a passkey) within your limit and at most 7 days
ago, by the phone that is linked now; the country and the network were seen in the user's earlier approved
sign-ins; the risk engine allows it with no risk signal; and the action is an everyday one. A critical action always
asks. In `shadow` mode (`SilentMode`) it always asks and the reasons say what would have happened.

Without the adapters:

```go
proof := r.Header.Get(touchque.GuardBrowserHeader)
risk, err := tq.Risk.Check(r.Context(), touchque.RiskCheckOptions{
    ExternalUsername: user, Type: "LOGIN", ClientIP: ip, UserAgent: r.UserAgent(), BrowserProof: proof,
})
if err == nil && !risk.Prompt {
    return openSession(user) // risk.Reasons say why
}
step, err := tq.Start("LOGIN", user, touchque.StartOptions{IP: ip, BrowserProof: proof}) // the approval makes the browser known

list, err := tq.Risk.Browsers(ctx, touchque.RiskBrowsersOptions{ExternalUsername: user})               // for an "approved browsers" list
res, err := tq.Risk.ForgetBrowsers(ctx, touchque.ForgetBrowsersOptions{ExternalUsername: user})        // all; or set Thumbprint for one
```

`Login.RequestWithOptions` takes `BrowserProof` too. Forget a user's browsers after a password reset or a "sign out
everywhere". `Risk.Check` reads the answer fail-closed: `Prompt` is `false` only when TouchQue answered the boolean
`false`.

## Never Locked Out (lost, dead or new phone)

A user whose phone is gone moves to a new phone without a help desk. Colleagues they named beforehand vouch on their own
phones, each typing a number the user reads them on a call; then a cooling-off (default 60 minutes) lets the old phone, any
voucher or an admin stop it. The risk engine can refuse it or ask for more vouchers, and for 24 hours afterwards critical
actions are refused. It is an option: offer it next to passkeys and the old phone's transfer, never as the only way. Every
step is a hash-chained receipt (`receipts`); a voucher's step carries the signature of their phone's hardware key.

```go
// Settings page, after an approval on the user's phone:
tq.Recovery.SetVouchers(ctx, user, []string{"bo@acme.com", "cy@acme.com"})

// "I lost my phone", after the password:
r, err := tq.Recovery.Start(ctx, touchque.StartRecoveryOptions{ExternalUsername: user, ClientIP: ip, DisplayName: "Ada", FallbackVouchers: admins})
showQR(r.BindURI)                        // the TouchQue app on the new phone scans it
now, _ := tq.Recovery.Status(ctx, r.RecoveryID) // each voucher's Code to read to them
// now.Status: AWAITING_DEVICE -> VOUCHING -> COOLING -> COMPLETED (or VETOED / EXPIRED / FAILED)

tq.Recovery.Veto(ctx, r.RecoveryID, "admin@acme.com", "") // an admin who does not believe it
```

## "Why?": case codes instead of guesswork

Every approval decision names a short case code (`K7P-2QX`: 6 characters, no I, O, 0 or 1). A user who was asked to
match a number, needed a passkey or was refused reads it out to your support team, and the team opens the whole
decision by it in the TouchQue dashboard (Logs → Look up a case): what went in, each check's verdict (the access rule
that matched, the risk signals that were acted on and the ones only measured), and the single change that would have
let it through. No screenshots, no log digging. The code opens nothing on its own: only your workspace sees its
decisions.

```go
step, err := tq.Start("WITHDRAW", user, touchque.StartOptions{IP: ip})
// step.CaseCode → "K7P-2QX"; step.Reasons → [{Code: "critical_action", Text: "The action is marked critical"}]
var apiErr *touchque.APIError
if _, err := tq.Login.Request(user, "LOGIN", "", "", "", false, false); errors.As(err, &apiErr) && apiErr.CaseCode != "" {
	show("Tell your support team: " + apiErr.CaseCode)
}
```

`CaseCode` is on `LoginRequestResponse`, `RiskCheckResult`, `APIError` and `Step` (the guard keeps it while it
waits); `Reasons` says why number matching or a passkey is needed.

## Blocking `VerifyWithOptions` and number matching

`client.Login.VerifyWithOptions` sends the request and waits for the phone in one call. With number matching (your
option, a workspace policy, a critical action or the risk engine can turn it on) the phone asks the user to pick a
number, and the call returns only after they have. Set `OnChallenge`: it runs once, right after the request is
created and before the wait. **Show `ChallengeCode` to the user now; the phone asks for it.**

```go
res, err := client.Login.VerifyWithOptions(touchque.LoginRequestOptions{
    ExternalUsername: user, Type: "SEND_MONEY",
    OnChallenge: func(c touchque.VerifyChallenge) {
        if c.ChallengeCode != "" {
            notifyUser("Pick "+c.ChallengeCode+" on your phone", c.CaseCode)
        }
    },
}, 30000)
```

`VerifyChallenge` has `RequestID`, `ChallengeCode` ("" without number matching), `ExpiresAt`, `Reasons` and
`CaseCode`. It is not called when only a passkey can approve (the call returns `*PasskeyRequiredError` first). A
panic in it is recovered and logged: the call keeps waiting. The positional `Login.Verify` has no callback. In a web
request, where the page hears nothing until you answer, use the relay or `client.Start`: their first answer already
carries the number.

## Verifying the device proof (no need to trust TouchQue)

Every approval from a phone with a hardware key carries `approvalProof`: the phone's own
signature over the request id, action, number-match code and the exact details it showed.

```go
ok := touchque.VerifyApprovalProof(event["approvalProof"], touchque.VerifyApprovalProofOptions{
    RequestID: requestID, Type: "WITHDRAW", Details: details, ChallengeCode: challengeCode,
    ExpectedPublicKey: user.TouchQueDeviceKey, // stored from their first verified approval
})
```

Without `ExpectedPublicKey` it returns false unless `AllowUnpinnedKey` is set (trust on first
use — store the proof's `PublicKey`, then pin it).

## Reporting fraud

Learned later that an approved request was fraud? Report it — it is the strongest signal
TouchQue's risk engine learns from, and it stays in your audit log:

```go
_, err := tq.Login.ReportFraud(requestID, touchque.ReportFraudOptions{Reason: touchque.FraudChargeback})
```

## Errors

`APIError`, `NetworkError`, `RejectedError`, `TimeoutError`,
`WebhookSignatureError`, `ConfigError` — check with `errors.As`.

## Security

- Every API request is signed HMAC-SHA256 (method, path+query, timestamp, nonce, body hash).
- The `X-TouchQue-Token` a frontend echoes back is itself signed and bound to
  one user + action + transaction digest.
- An approval is consumed exactly once, server-side.
- Your API secret never leaves your server.

See [SECURITY.md](./SECURITY.md) to report a vulnerability.

## Requirements

- Go 1.26+ (the module's go directive)
- A [TouchQue Dashboard](https://authenticator.touchque.com) account

## License

MIT © [TouchQue](https://touchque.com)
