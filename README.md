# touchque-go

The official Go server SDK for [TouchQue](https://touchque.com) — biometric push
2FA, passkeys, and offline approval codes, added to any `net/http` backend
with one middleware wrap per route.

[![Go Reference](https://pkg.go.dev/badge/github.com/Touchque/touchque-go/v3.svg)](https://pkg.go.dev/github.com/Touchque/touchque-go/v3)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

📘 Full docs: **[authenticator.touchque.com/docs](https://authenticator.touchque.com/docs)**

## Install

```bash
go get github.com/Touchque/touchque-go/v3
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
import "github.com/Touchque/touchque-go/v3/touchque"

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
| `POST /login` | same two-phase contract as `Require`: `202 {"touchque": step, "token"}` until approved |
| `POST /offline/challenge`, `/offline/verify`, `/offline/totp` | off (403 `OFFLINE_REQUIRES_FIRST_FACTOR`) unless `LoginUser` or `AllowOfflineWithoutFirstFactor` is set |
| `POST /passkey/authenticate/options`, `/passkey/authenticate/verify` | passwordless sign-in |
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
event, err := tq.Webhook.Verify(rawBody, r.Header.Get("X-TouchQue-Signature"))
if err != nil {
    w.WriteHeader(http.StatusForbidden) // not from TouchQue
    return
}
```

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
