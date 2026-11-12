# touchque-go

The official Go server SDK for [Touchque](https://touchque.com) — biometric push
2FA, passkeys, and offline approval codes, added to any `net/http` backend
with one middleware wrap per route.

[![Go Reference](https://pkg.go.dev/badge/github.com/Touchque/touchque-go/v5.svg)](https://pkg.go.dev/github.com/Touchque/touchque-go/v5)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

📘 Full docs: **[support.touchque.com](https://support.touchque.com)**

## Install

```bash
go get github.com/Touchque/touchque-go/v5
```

## Setup

Get an API key and secret from your [Touchque Dashboard](https://dashboard.touchque.com):

```bash
export TQ_API_KEY=tq_auth_your_key
export TQ_API_SECRET=your_api_secret
```

`touchque.New()` reads these from the environment (and `TQ_API_URL` when set).
`touchque.NewClient(&touchque.Config{APIKey: ..., APISecret: ...})` takes them
in code instead; it panics when they are missing or invalid.

## Quick start (net/http)

```go
import "github.com/Touchque/touchque-go/v5/touchque"

tq, err := touchque.New() // TQ_API_KEY, TQ_API_SECRET
if err != nil {
    log.Fatal(err)
}

mux.Handle("/transfer", touchque.Require(tq, "SEND_MONEY", http.HandlerFunc(transferHandler), touchque.RequireOptions{
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
header `X-Touchque-Token: <token>` — see
[`@touchque/web`](https://www.npmjs.com/package/@touchque/web), which does
this loop for you in the browser. Once approved, the retried request reaches
`next` exactly once.

While the first-time QR is up, polls answer `{"touchque": {"state": "enroll", "expiresAt": ...}}` without
`enroll`: keep showing the QR you have. About 15 seconds before it expires, a poll brings a new QR in
`enroll.qrCodeDataUrl` together with new recovery codes: the old QR and the old codes stop working, so
show the new ones. Pages on `@touchque/web` need 2.1.0.

While the push waits, every poll carries the request's `expiresAt` in the `waiting` (or
`passkey_required`) step, so a page that reads it from the latest answer stops in time. It is the
request's live expiry: when the Vishing Shield moves a push to a passkey, the request stays open 180
seconds longer for the ceremony, and the polls say so.

A guard that may not show a first-time QR (`GuardInput.NoEnroll`, the relay's `POST /login` without
`LoginUser`, passkey registration) answers a user with no phone 202
`{"touchque": {"state": "enroll", "reason": "enrollment_off"}}`: no QR is coming, so stop polling and
ask the user to link the Touchque app first (`@touchque/web` 2.2.0 does).

A 202 state other than `waiting` and `enroll` (`passkey_required`, `offline`, an `enroll` step with a
`reason`) needs `@touchque/web`, or your own UI following the contract.

### Refusals in your own error shape

A refusal answers 401 (nobody signed in), 403 (`rejected`, `blocked`), 408 (`expired`), 423 (`frozen`) or
429 (`rate_limited`, both with `Retry-After`), and 500 `misconfigured` / 503 `unavailable` when Touchque is
not set up or cannot be reached. The body is `{"touchque": {"state": ..., "reason": ...}}`, with
`"error": {"code", "message"}` on 401, 500 and 503. `RequireOptions.ErrorBody` sends your app's own shape
instead:

```go
mux.Handle("/transfer", touchque.Require(tq, "SEND_MONEY", http.HandlerFunc(transferHandler), touchque.RequireOptions{
    User: func(r *http.Request) string { return sessionUser(r) },
    ErrorBody: func(r touchque.GuardRefusal) any {
        return map[string]string{"message": r.Message, "code": r.Code}
    },
}))
// 403 {"code":"rejected","message":"The approval was rejected.","touchque":{"state":"rejected",...}}
```

It is called for every answer with status 400 or above, never for a 202 step, with a
`touchque.GuardRefusal`: `Status`; `Code` (the guard's error code, else the step's `Reason`, else its
`State`); `Message` (the guard's error message, else "The approval was rejected.", "The approval
expired. Try again.", "Too many rejected approvals. Try again later.", "Too many attempts. Try again
later." or "The approval was refused."); and `Touchque`, a copy of the step. What it returns counts by
its JSON encoding: a value that encodes to a JSON object (a map, a struct) is sent with `touchque` set to
the step, so `@touchque/web` still sees the state (no `token` is added); anything else (a string, a
number, a slice, nil) is sent as it is. The status and headers stay. A panic, or a value
`encoding/json` cannot encode, sends the default body and logs `[Touchque] ErrorBody failed` (see
[Logging](#logging)).

Every refusal (status 400 and above) from `Require` and from the relay also carries
`X-Touchque-State: <state>`, and `X-Touchque-Reason: <reason>` when the step has one: `@touchque/web`
2.1.0 reads the step from them when the body has no `touchque`. A page on another origin needs them in
`Access-Control-Expose-Headers`.

### Without API keys

`Require(nil, ...)` builds the client from `TQ_API_KEY` / `TQ_API_SECRET` (`touchque.New()`) on the first
request, and keeps it once built:

```go
mux.Handle("/transfer", touchque.Require(nil, "SEND_MONEY", http.HandlerFunc(transferHandler), touchque.RequireOptions{
    User:   func(r *http.Request) string { return sessionUser(r) },
    Logger: logger, // optional *slog.Logger: Require's lines and, with a nil client, the guard's
}))
```

While the keys are not set, the route answers **500**
`{"touchque": {"state": "blocked", "reason": "misconfigured"}, "error": {"code": "misconfigured",
"message": "Two-factor approval is not configured correctly."}}` with `Cache-Control: no-store` (401
`unauthenticated` when nobody is signed in), `next` never runs, and nothing panics (`Require` still
panics without `User`: that is a wiring bug). With `RequireOptions.Logger` set,
`[Touchque] TQ_API_KEY and TQ_API_SECRET are not set: routes guarded by Touchque answer 500 misconfigured.`
is logged once per process. It is a 500, not a 503: a deploy mistake should show in your monitoring, not
invite retries. `@touchque/web` shows "Approvals are not set up correctly on this site."
`RunGuard(ctx, nil, …)` and `IsStatusPoll(nil, …)` use the same default client: one per process, built
on first use, shared with every `Require(nil, …)` and safe for concurrent use; a failed build is tried
again on the next request. Once built, it keeps what it read: the environment is read once per process
unless you reset it. `touchque.SetDefaultClient(nil)` forgets the client, so the next call builds it
again from the environment (a test that points `TQ_API_URL` elsewhere, a rotated key), and
`touchque.SetDefaultClient(tq)` replaces it.

The startup check, to fail fast instead of answering 500 `misconfigured`, builds the client yourself and
makes it the default:

```go
tq, err := touchque.New() // or touchque.New(cfg)
if err != nil {
    log.Fatal(err) // the ConfigError names the missing keys
}
touchque.SetDefaultClient(tq) // Require(nil, …), RunGuard(ctx, nil, …) and IsStatusPoll(nil, …) use it
```

The client built from the environment logs nothing. To give the null-client path a logger, build it with
`touchque.New(cfg)`, where `cfg` comes from `touchque.ConfigFromEnv()` with `cfg.Logger` set.

`New()` and `NewClient` are unchanged.

## Guard inside your handler

When your own checks come first (the balance, who owns the account), call `RunGuard` in the handler
instead of wrapping it in `Require`. It is the same guard and never panics for Touchque. Pass a nil
client: the default one is built from `TQ_API_KEY` / `TQ_API_SECRET` on the first request and shared with
`Require(nil, …)`, so nothing fails at startup without the keys (the route answers 500 `misconfigured`, as
above). Do the action once `Approved` is set; otherwise `touchque.WriteGuardResult(w, res, errorBody)`
sends what `Require` sends: `Status`, the headers (`Content-Type: application/json`,
`Cache-Control: no-store`, `Retry-After` on 423 and 429, `X-Touchque-State` and `X-Touchque-Reason` on a
refusal) and the JSON body, with `errorBody` (nil for the default body) applied as
`RequireOptions.ErrorBody` is:

```go
func transfer(w http.ResponseWriter, r *http.Request) {
    user := sessionUser(r)
    amount, err := strconv.Atoi(r.FormValue("amount"))
    if err != nil || amount > balanceOf(user) { // your checks first: no push for a transfer you refuse anyway
        http.Error(w, "insufficient funds", http.StatusBadRequest)
        return
    }

    res := touchque.RunGuard(r.Context(), nil, touchque.GuardInput{ // nil: the default client (TQ_API_KEY / TQ_API_SECRET)
        User: user, Action: "SEND_MONEY",
        // The same on every poll: build them from your own state.
        Details:   []touchque.LoginDetail{{Label: "Amount", Value: strconv.Itoa(amount) + " EUR"}},
        IP:        clientIP(r), // the end user's address (see the Quick start)
        UserAgent: r.UserAgent(),
        Token:     r.Header.Get(touchque.GuardTokenHeader),
        Offline:   r.Header.Get(touchque.GuardOfflineHeader) == "1",
        Code:      r.Header.Get(touchque.GuardCodeHeader),
        CodeType:  r.Header.Get(touchque.GuardCodeTypeHeader),
    })
    if res.Approved == nil {
        touchque.WriteGuardResult(w, res, nil) // or your own func(touchque.GuardRefusal) any, as ErrorBody
        return
    }

    sendMoney(user, amount) // once: the approval is used up
    _ = json.NewEncoder(w).Encode(map[string]any{"ok": true, "approval": res.Approved})
}
```

The answers are `Require`'s. 202 `{"touchque": step, "token": ...}` until the phone answers: the page
shows the step and sends the request again with `X-Touchque-Token` (`@touchque/web` does), and
`Approved` comes exactly once, for this user, action and details. Every `waiting` / `passkey_required`
poll carries the request's live `expiresAt`. While the first-time QR is up the 202 step is
`{"state": "enroll", "expiresAt": ...}` without `enroll`: keep the QR on screen. About 15 seconds before
it expires a poll brings a new QR in `enroll.qrCodeDataUrl` with new recovery codes, and the old QR and
codes stop working. With `NoEnroll` a user with no phone gets
`{"state": "enroll", "reason": "enrollment_off"}`: stop polling. A 202 state other than `waiting` and
`enroll` (`passkey_required`, `offline`, an `enroll` step with a `reason`) needs `@touchque/web`, or your
own UI following the contract. A refusal is 401, 403, 408, 423 or 429; 500 `misconfigured` and 503
`unavailable` when Touchque is not set up or cannot be reached.

With a rate limit of your own in front of it, count a request that only polls
(`touchque.IsStatusPoll(nil, in)`, nil for the default client as in `RunGuard`: it reads the status, or
keeps the first-time QR) apart from a new attempt, and set `in.BeforeStart`: `RunGuard` calls it at most
once, right before a first-time-QR token would start something after all (a push now that the phone is
linked, or a new QR). Charge your per-user limit there and return your 429 as a `*touchque.GuardResult` to
answer it instead, or nil to go on. The relay does this for `POST /login`.

## Action types

`"SEND_MONEY"` above is an action type: one kind of approval, with the title the phone shows and
whether it is critical. Define each one once, in the dashboard (**Developers → Action types**)
or from code:

```go
critical := true
_, err := client.ActionTypes.Define("SEND_MONEY", touchque.DefineOptions{Name: "Send money", Critical: &critical})
```

The guard refuses what is not ready. A name that is not defined is a setup error
(`*touchque.ConfigError`, "touchque: unknown action …"): the guard answers 500 with `reason: "misconfigured"`. A type
turned off in the dashboard answers 403 with `reason: "action_disabled"`, which stops that kind of
approval at once, without a deploy.

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
  `/passkey/login/verify` only open a session for the user Touchque reports if
  it matches. `OnAuthenticated` always receives Touchque's user, never one from
  the body.
- Pre-auth routes are rate limited in memory, per route: 20 requests per IP and
  5 per username per minute (429 `RATE_LIMITED` + `Retry-After`). Tune with
  `RateLimit: &touchque.RateLimitOptions{...}`, or set `Disabled: true` if you
  limit in front. Set `IP` behind a reverse proxy (default: the host of
  `r.RemoteAddr`).
- Touchque client errors are forwarded with their machine-readable code only;
  5xx and network failures become 502 `relay_error`. JSON bodies are read only
  with `Content-Type: application/json`, up to 100 KiB.

## The three primitives, if you're not using `Require`

```go
details := []touchque.LoginDetail{{Label: "Amount", Value: "250 EUR"}}
step, err := tq.Start("SEND_MONEY", "jane@acme.com", touchque.StartOptions{Details: details})
// step.State: touchque.StepWaiting (show step.Number) | touchque.StepEnroll (show step.Enroll.QRCodeDataURL)
//             | StepApproved | StepRejected | StepExpired | StepPasskeyRequired | StepFrozen | StepBlocked

latest, err := tq.Check(step.RequestID) // latest.State

// Once approved, consume it exactly once, right before doing the protected thing:
approval, err := tq.Complete(step.RequestID, "jane@acme.com", "SEND_MONEY", touchque.CompleteExpect{Details: details})
```

`Complete` verifies the approval was actually issued for this user, action
and transaction, and can only be consumed once.

## Passkeys (phishing-resistant)

Push approval and offline codes stop password reuse and push fatigue, but a
real-time phishing proxy can still relay them. A passkey can't be phished —
the browser signs your site's real origin, and Touchque refuses any other
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
rawBody, _ := io.ReadAll(r.Body) // the body exactly as received
event, err := tq.Webhook.Verify(string(rawBody), r.Header.Get("X-Signature"))
if err != nil {
    w.WriteHeader(http.StatusForbidden) // not from Touchque
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

The phone tells Touchque, signed with its hardware key, whether a call was active (or just ended), the screen
was shared or the phone remote-controlled when the user tapped Approve. Depending on the server's mode:

- **Passkey instead.** A user with a passkey finishes in the browser: the request stays open and turns into
  `passkey_required` mid-flight. The step-up flow and the relay handle it; the blocking `Login.VerifyWithOptions` returns
  `*touchque.PasskeyRequiredError` (`Reason == "step_up"`). No offline or recovery code can finish such a request.
- **Refused.** A critical action without a passkey is rejected (`reason: vishing_suspected`).
- **Provisional.** Anything else is approved with `Provisional` set on `Approval` from `Complete`. Let the user
  in, but treat the session as limited: Touchque refuses the user's critical actions (`blocked` / `provisional`)
  until the phone re-confirms after the call (`APPROVAL_RECONFIRMED`). `APPROVAL_REVOKED` (`reason` `COACHED` or
  `UNDO`) means end the session; an approval revoked before you consumed it can no longer be consumed
  (409 `revoked`).

**Mirror Alarm.** The first waiting step carries `canary.url`. `@touchque/web` loads it on the page showing the
sign-in and sends a beacon to it, so a real-time phishing proxy in front of your site shows up as itself: the
approval is refused (`reason: phishing_origin`) and the phone warns the user. Allow the canary host in your
Content-Security-Policy (`img-src` and `connect-src`).

## Touchque Actions (your code in the approval pipeline)

Alerts, step-ups and refusals by country, local time, role or amount, passkeys
for admins — from a template or a few lines of JavaScript, replayed against your
real recent sign-ins before they go live. Full guide: [support.touchque.com/actions](https://support.touchque.com/actions).

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

## AI agents (an identity per agent, never your API key)

Register each agent with its **public** key; the private key stays where the agent runs. The agent signs in
with its own key and gets a 10-minute token bound to that key (DPoP).

```go
keys, _ := touchque.GenerateAgentKey("ES256") // or where the agent runs
agent, err := client.Agents.Create(touchque.CreateAgentParams{
	Name: "Invoice bot", AllowedTypes: []string{"PAY_INVOICE"}, PublicKey: keys.PublicJWK,
	OwnerEmail: "ada@acme.com", // accountable; the agent stops if they leave
})
// store agent.ID and keys.PrivateJWK in the agent's secrets (TQ_AGENT_ID, TQ_AGENT_KEY)

a, _ := touchque.NewAgent(touchque.AgentConfig{}) // in the agent
me, err := a.Me()
```

`client.Agents.Suspend(id, reason)` stops one agent at once, `client.Agents.SetKillSwitch(true, reason)` every agent.

```go
ask, _ := a.RequestApproval(touchque.AgentApprovalParams{User: "jane@example.com", Type: "PAY_INVOICE", Reason: "October rent",
	AuthorizationDetails: []map[string]interface{}{{"type": "payment_initiation",
		"instructedAmount": map[string]interface{}{"currency": "TRY", "amount": "500.00"},
		"creditorName": "Jane Doe", "creditorAccount": map[string]interface{}{"iban": "TR330006100519786457841326"}}}})
done, err := a.WaitForApproval(ctx, ask.ApprovalID, 0, 0)

// in your executor, right before paying: used once, only for what you are about to do
approval, err := client.Agents.RedeemApproval(done.ApprovalToken, touchque.ApprovalExpectation{User: "jane@example.com", Type: "PAY_INVOICE",
	AuthorizationDetails: map[string]interface{}{"type": "payment_initiation", "instructedAmount": map[string]interface{}{"currency": "TRY", "amount": "500.00"}}})
```


### Cross App Access (ID-JAG) and A2A agent cards

An organization's identity provider (Touchque SSO) can let one of its apps reach another service for a member with no consent screen (Cross App Access, ID-JAG, an open IETF draft): the app trades the member's ID token for an ID-JAG, then the ID-JAG for an access token at the other service. If you run an authorization server, the verifier checks an ID-JAG (issuer, single audience, your client, expiry, `typ`) and uses it once. Before your agent trusts another agent's A2A card, check its signatures (A2A 1.0 §8.4: JWS over the RFC 8785 canonical card); keys named by `jku` are only fetched from the card's own host or hosts you trust.

```go
jag, err := touchque.RequestIDJAG(ctx, touchque.RequestIDJAGParams{Issuer: "https://sso.touchque.com",
	ClientID: clientID, ClientSecret: secret, IDToken: idToken, Audience: "https://auth.files.example"})
tokens, err := touchque.RedeemIDJAG(ctx, touchque.RedeemIDJAGParams{TokenEndpoint: "https://auth.files.example/token",
	ClientID: "acme", ClientSecret: filesSecret, Assertion: jag.Assertion})

// Your own authorization server (jwt-bearer grant):
v, _ := touchque.NewIDJAGVerifier(touchque.IDJAGVerifierConfig{Issuer: "https://sso.touchque.com", Audience: "https://auth.files.example"})
claims, err := v.Verify(ctx, r.PostFormValue("assertion"), authenticatedClientID)

res, err := touchque.VerifyAgentCard(ctx, cardJSON, touchque.VerifyAgentCardOptions{CardURL: "https://agent.example/.well-known/agent-card.json"})
```

## Silent sign-ins (stop asking when nothing is new)

A user who approved on their phone in this browser a little while ago, from the same phone, network and country,
with no risk signal since, does not need another push. Touchque's risk engine decides; your server only skips the
push when it says so.

1. In the browser, `@touchque/web` 2.0.0 with `createTouchqueWeb({ browserKey: true })` keeps a non-extractable
   key for your site and sends a fresh, signed proof of it in the `X-Touchque-Browser` header
   (`touchque.GuardBrowserHeader`).
2. On the server, turn on `SilentSignIn`:

```go
mux.Handle("/login/2fa", touchque.Require(tq, "LOGIN", http.HandlerFunc(signInHandler), touchque.RequireOptions{
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

Touchque only lets a sign-in through silently when all of this holds: the browser proved its key and was approved
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
everywhere". `Risk.Check` reads the answer fail-closed: `Prompt` is `false` only when Touchque answered the boolean
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
showQR(r.BindURI)                        // the Touchque app on the new phone scans it
now, _ := tq.Recovery.Status(ctx, r.RecoveryID) // each voucher's Code to read to them
// now.Status: AWAITING_DEVICE -> VOUCHING -> COOLING -> COMPLETED (or VETOED / EXPIRED / FAILED)

tq.Recovery.Veto(ctx, r.RecoveryID, "admin@acme.com", "") // an admin who does not believe it
```

## "Why?": case codes instead of guesswork

Every approval decision names a short case code (`K7P-2QX`: 6 characters, no I, O, 0 or 1). A user who was asked to
match a number, needed a passkey or was refused reads it out to your support team, and the team opens the whole
decision by it in the Touchque dashboard (Logs → Look up a case): what went in, each check's verdict (the access rule
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

## Verifying the device proof (no need to trust Touchque)

Every approval from a phone with a hardware key carries `approvalProof`: the phone's own
signature over the request id, action, number-match code and the exact details it showed.

```go
ok := touchque.VerifyApprovalProof(event["approvalProof"], touchque.VerifyApprovalProofOptions{
    RequestID: requestID, Type: "WITHDRAW", Details: details, ChallengeCode: challengeCode,
    ExpectedPublicKey: user.TouchqueDeviceKey, // stored from their first verified approval
})
```

Without `ExpectedPublicKey` it returns false unless `AllowUnpinnedKey` is set (trust on first
use — store the proof's `PublicKey`, then pin it).

## Reporting fraud

Learned later that an approved request was fraud? Report it — it is the strongest signal
Touchque's risk engine learns from, and it stays in your audit log:

```go
_, err := tq.Login.ReportFraud(requestID, touchque.ReportFraudOptions{Reason: touchque.FraudChargeback})
```

## VPN and other RADIUS clients (`RadiusClient`)

The Touchque RADIUS proxy (a program your company runs next to its VPN) asks
Touchque SSO for the second factor of a VPN sign-in through `RadiusClient`. You
only need it to build your own RADIUS server. The key and secret are a VPN app's
proxy credential (dashboard: Organization → VPN & RADIUS); requests are signed
like every Touchque API call.

```go
rc, err := touchque.NewRadiusClient(&touchque.Config{APIKey: "tq_rad_…", APISecret: secret})
app, err := rc.Config(ctx, touchque.RadiusProxyInfo{Version: "1.0.0", Clients: 1})
d, err := rc.Authenticate(ctx, touchque.RadiusAuthRequest{
    Username: "jdoe", PrimaryVerified: true, // your directory checked the password
    NAS: touchque.RadiusNAS{IP: "10.0.0.1"}, Client: touchque.RadiusEndUser{IP: "85.105.10.20"},
})
switch d.Decision {
case "challenge": // show d.Number in an Access-Challenge; when the user presses OK:
    d, err = rc.Wait(ctx, d.TransactionID, 20*time.Second) // or rc.Passcode(ctx, d.TransactionID, code)
case "pending": // a plain push
    d, err = rc.Wait(ctx, d.TransactionID, 20*time.Second)
}
// "accept", "reject" (d.Reason, d.CaseCode), or "pending" after Wait: ask again.
```

## Pairing a browser by QR code

Your page shows a QR code, the person scans it with the Touchque app, and the phone that scanned is the one asked to approve, with number matching. Your page sends the thumbprint of its browser key (`@touchque/web` `browserKey.thumbprint()`); the nonce in the QR never leaves your server (Touchque keeps its hash).

```go
p, err := client.QRPairings.Create(ctx, touchque.CreateQRPairingOptions{KeyThumbprint: thumb, ClientIP: ip, UserAgent: r.UserAgent()})
// show p.URI (touchque://pair-browser?...) as a QR code; poll:
now, err := client.QRPairings.Get(ctx, p.PairingID) // waiting -> scanned -> confirmed
if now.State == "confirmed" {
	_, err = client.Login.RequestWithOptions(touchque.LoginRequestOptions{ExternalUsername: now.ExternalUsername, Type: "LOGIN", QRPairing: p.PairingID})
}
// or: client.QRPairings.Refuse(ctx, p.PairingID, touchque.RefuseQRPairingOptions{Reason: "device_not_approved", Message: "Ask IT to approve this computer."})
```

`get` says `scanned` / `confirmed` once a phone holding one of your users' accounts read it (with `proximity`: same network, same country), `reported` when the person said someone told them to scan it (their 2FA freezes). `refuse` tells the phone why your own checks said no.

## A code typed back on the phone

When a sign-in needs a code another service sent the person (a text message, WhatsApp, e-mail), ask them to type it on the phone instead. The phone encrypts it to a one-time key you made for this request: Touchque only ever holds the ciphertext. Such a request lives 5 minutes.

```go
key, err := touchque.NewCodeReplyKey() // keep key.PrivateKey for this request
sent, err := client.Login.RequestWithOptions(touchque.LoginRequestOptions{ExternalUsername: user, Type: "LOGIN",
	Reply: &touchque.LoginReplyRequest{Kind: "code", Key: key.PublicKey, Channel: "sms", Target: "+**********26"}})
status, err := client.Login.Status(sent.RequestID) // once CONFIRMED
if status.Reply != nil {
	code, ok := touchque.OpenCodeReply(key.PrivateKey, sent.RequestID, status.Reply.CT)
}
```

## Safe Guard (Safe transactions approved on the phone)

TouchqueSafeGuard is a transaction guard for a Safe: a transaction runs only with approvals signed by the P-256 keys on its approvers' phones. You send the raw transaction; the phone decodes it itself, shows its own rows and signs what it computed with a key only its biometrics unlock. Delegatecalls, changes to the Safe and proxy upgrades are governance: scheduled, time-locked and vetoable. A phone without that key yet gets `409 crypto_key_missing`.

```go
target := touchque.SafeTxTarget{ChainID: "1", Safe: safe, Guard: guard,
	Tx: touchque.SafeTxCall{To: to, Value: "0", Data: data, Operation: 0, Nonce: "42"}}
sent, err := client.SafeGuard.Request(ctx, touchque.SafeGuardRequestOptions{
	ExternalUsername: "treasurer@acme.com",
	Type:             "safe_payment", // an action type from your dashboard
	SafeTx: touchque.SafeGuardTx{SafeTxTarget: target,
		Config:        touchque.SafeGuardConfig{Threshold: 2, GovThreshold: 3, GovDelay: 172800, ExitDelay: 259200},
		BatchTargets:  []string{multiSendCallOnly},
		ApproverIndex: 0}, // this approver's index in the guard
})
done, err := client.SafeGuard.WaitForApproval(ctx, sent.RequestID, 0, 0) // 5 minutes at most
approval := done.SafeTx.Approval

// Check it yourself: your own transaction, the approver's key from the guard on chain,
// and the purpose you will act on ("approve" executes, "schedule" starts a governance change).
index := 0
check, err := touchque.VerifySafeApproval(target, approval, approverKey, touchque.VerifySafeApprovalOptions{Purpose: done.SafeTx.Purpose, ApproverIndex: &index})
if err != nil || !check.Valid {
	return fmt.Errorf("approval refused: %s", check.Reason)
}
if check.Purpose == "approve" {
	signatures, _ := touchque.WithSafeApprovals(ownerSignatures, []string{approval}) // execTransaction(…, signatures)
} else {
	calldata, _ := touchque.SafeScheduleCall(safe, check.GovernanceHash, []string{approval}) // a call to the guard; runs after govDelay
}
```

`VerifySafeApproval` makes the guard's check off chain, so a co-signer or your own server never has to trust Touchque: it computes the Safe transaction hash (EIP-712) and the governance hash from the raw fields, rebuilds the 149-byte message the phone signed and checks the P-256 signature. It refuses a high `s`, an approval that expired or is valid for more than a day, another approver index, and, when you pass `Rows` or `DisplayDigest` from your own decoding, rows the phone did not show. Without `Purpose` only an ordinary approval (`approve`) is valid: a `schedule` approval covers the governance hash, which has no Safe nonce, so it passes only when you name `Purpose: "schedule"`. `Reason` is `approval_malformed`, `public_key_invalid`, `approver_index_mismatch`, `approval_expired`, `rows_differ`, `high_s` or `signature_invalid`; an error only means the target is not a Safe transaction. `SafeTxHash`, `SafeGovernanceHash`, `SafeApprovalMessage` and `SafeDisplayDigest` are exported too. Standard library only.

## Shared Signals (security events from Touchque SSO)

Touchque SSO tells your app when something happens to a member's account after sign-in: an admin ended their sessions,
a password or 2FA method changed, a device fell out of compliance, the account was disabled or a credential leaked. It
sends Security Event Tokens (SETs, OpenID Shared Signals Framework 1.0) to the receivers an organization's admin adds
(Organization > Continuous access), pushed to your endpoint (RFC 8935) or waiting for you to poll (RFC 8936). End the
person's sessions, or ask them to sign in again.

```go
v, _ := touchque.NewSecurityEventVerifier(touchque.SecurityEventVerifierConfig{
	Issuer:   "https://sso.touchque.com",
	Audience: "https://app.example.com", // your stream's aud, as the dashboard shows it
})

// Push: the SET is the request body (application/secevent+jwt).
http.HandleFunc("/ssf", func(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(io.LimitReader(r.Body, 32<<10))
	event, err := v.Verify(r.Context(), string(body))
	var se *touchque.SecurityEventError
	if errors.As(err, &se) {
		if se.Code == "temporarily_unavailable" {
			w.WriteHeader(503) // the keys could not be read: the transmitter tries again
			return
		}
		w.WriteHeader(400)
		json.NewEncoder(w).Encode(map[string]string{"err": se.Code, "description": se.Message})
		return
	}
	if event.Name == "session-revoked" {
		endSessionsOf(event.Subject["email"])
	}
	w.WriteHeader(202)
})

// Poll: acknowledge what you handled, get what is waiting.
var ack []string
for {
	out, err := touchque.PollSecurityEvents(ctx, touchque.PollSecurityEventsParams{
		URL: pollURL, Token: streamToken, Ack: ack, // the stream's endpoint_url and token
	})
	if err != nil {
		return err // *SecurityEventError with the transmitter's code, or a network error
	}
	ack = nil
	for jti, set := range out.Sets {
		if event, err := v.Verify(ctx, set); err == nil {
			handle(event)
		}
		ack = append(ack, jti)
	}
}
```

`Name` is the short name (`session-revoked`, `credential-change`, `device-compliance-change`, `account-disabled`,
`credential-compromise`; `SecurityEventTypes` maps each to its URI), `Subject` the person
(`{"format": "email", "email": ...}`) and `TXN` the case code of Touchque's decision. The keys come from the issuer's
`/.well-known/ssf-configuration` (or set `JWKSURI` / `JWKS`). A SET does not expire: keep the jtis you handled and skip
a repeat.

## Errors

`APIError`, `NetworkError`, `RejectedError`, `TimeoutError`,
`WebhookSignatureError`, `ConfigError` — check with `errors.As`.

A feature your organization cannot use here comes back as a 403 `*APIError` with `Feature` set (`device_risk`, `ai_agents`…); match it with `errors.Is(err, touchque.ErrFeatureNotInPlan)`, `ErrFeatureReadOnly` or `ErrFeatureOff` (`ErrFeature` for any of them) — not in its plan (an owner or admin adds it in the Touchque dashboard), being turned off (reads work for 14 days, changes are refused) or switched off on this Touchque deployment.

## Security

- Every API request is signed HMAC-SHA256 (method, path+query, timestamp, nonce, body hash).
- The `X-Touchque-Token` a frontend echoes back is itself signed and bound to
  one user + action + transaction digest.
- An approval is consumed exactly once, server-side.
- Your API secret never leaves your server.

See [SECURITY.md](https://github.com/Touchque/touchque-go/blob/main/SECURITY.md) to report a vulnerability.

## Requirements

- Go 1.26+ (the module's go directive)
- A [Touchque Dashboard](https://dashboard.touchque.com) account

## Logging

The SDK writes nothing to the standard `log` package. To see its own problems (a misconfigured guard, a failed `OnChallenge` or `ErrorBody`, a relay without `LoginUser`), set `Config.Logger` to a `*slog.Logger`; nil, the default, logs nothing. `Require(nil, …)` has no `Config`: set `RequireOptions.Logger` there, which also hears about missing `TQ_API_KEY` / `TQ_API_SECRET` (once per process). `RunGuard(ctx, nil, …)` and `WriteGuardResult` log through the client's `Config.Logger`: with a nil client, the default client's, which logs nothing unless you set one with `touchque.SetDefaultClient` (see [Without API keys](#without-api-keys)). Lines carry an error's type and text, never the request.

## License

MIT © [Touchque](https://touchque.com)

## Touchque Login (hosted sign-in)

Sign-up and sign-in pages for your own customers, on your brand, with OpenID Connect. See [support.touchque.com/touchque-login](https://support.touchque.com/touchque-login) for this SDK's client and a quickstart.
