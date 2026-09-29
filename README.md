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

`touchque.NewClient(touchque.Config{})` reads these from the environment when
left empty.

## Quick start (net/http)

```go
import "github.com/Touchque/touchque-go/v3/touchque"

tq := touchque.NewClient(touchque.Config{})

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

Until the user approves on their phone, `Require` answers
**`202 {"touchque": step, "token": "..."}`** instead of calling `next`. Your
frontend renders `step` in its own UI (a matching number, or a QR code the
first time the user links the app) and sends the same request again with
header `X-TouchQue-Token: <token>` — see
[`@touchque/web`](https://www.npmjs.com/package/@touchque/web), which does
this loop for you in the browser. Once approved, the retried request reaches
`next` exactly once.

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
ch, _ := tq.Offline.Challenge(ctx, touchque.OfflineChallengeOptions{
    User: "jane@acme.com", Type: "WITHDRAW",
    Details: []touchque.LoginDetail{{Label: "Amount", Value: "1,250.00 USD"}},
})
// show ch.QRDataURL — the phone scans it offline and shows a 7-character code
result, _ := tq.Offline.Verify(ctx, ch.ChallengeID, code)
```

## Webhooks

```go
event, err := tq.Webhook.Verify(rawBody, r.Header.Get("X-TouchQue-Signature"))
if err != nil {
    w.WriteHeader(http.StatusForbidden) // not from TouchQue
    return
}
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

- Go 1.21+
- A [TouchQue Dashboard](https://authenticator.touchque.com) account

## License

MIT © [TouchQue](https://touchque.com)
