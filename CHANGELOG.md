# Changelog

All notable changes to this project will be documented in this file. The
format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

Go modules are versioned via git tags (e.g. `touchque-go/v1.1.0`), not a
manifest field — the version below corresponds to the tag this SDK should
be released under next.

## [3.4.0] — 2026-10-18

### Added
- **Vishing Shield.** When the user taps Approve during a call (or with the screen shared or the phone
  remote-controlled), TouchQue can move the request to a passkey, refuse it, or approve it as provisional.
  `Approval`, `LoginStatusResponse`, `ConsumeResponse` (embedded `ShieldFields`) and `VerifyResponse.Provisional` carry `provisional`, `revoked`, `revokeReason` and
  `reconfirmedAt`: a provisional approval lets the user in, but TouchQue refuses their critical actions
  (`blocked` / `provisional`) until the phone re-confirms it after the call.
- `Reason*` and `Event*` constants for the webhook reasons (`vishing_suspected`, `phishing_origin`,
  `user_reported_coached`, and the existing ones) and events (`APPROVAL_RECONFIRMED`, `APPROVAL_REVOKED`, and
  the existing ones).
- **Mirror Alarm.** The first waiting step carries `Step.Canary` (`LoginRequestResponse.Canary`); `@touchque/web` 1.3.0 loads it on the page
  that shows the sign-in, so a real-time phishing proxy gets the approval refused (`phishing_origin`). Allow
  the canary host in your CSP (`img-src`, `connect-src`).

### Changed (behaviour)
- **`Login.Verify` / `Login.VerifyWithOptions` return `*PasskeyRequiredError` (`Reason == "step_up"`) when a poll shows the request now needs a passkey** (PENDING with
  `requiresPasskey`), instead of polling into a timeout. Finish it in the browser with `@touchque/web`. The
  error has a new `Reason` field (`""` for the passkey-only policy, as before).
- The guard switches a waiting offline QR to `passkey_required` when its push moved to a passkey, and an
  offline code TouchQue refuses for that reason answers `passkey_required` instead of `blocked`.
- An approval the user took back on the phone answers the guard with `expired` / `revoked`.

## [3.3.0] — 2026-10-12

### Fixed
- **`Require` sent `r.RemoteAddr` with its port** (`"203.0.113.7:51234"`). That is not an address, so the
  API scored your server's address instead of the user's: Tor, location, travel and the location shown
  on the phone were all blind, and every user of your app looked like one IP. The default is now the
  host part, like the relay's.
- **Waiting on an approval no longer hits the rate limit.** Each browser poll of `/login` counted against
  the per-user limit (5 a minute), so a user who took more than about 7.5 s to approve got a 429 while
  the push was still on the phone. A poll that carries a valid, still-waiting token only reads the
  status and now has its own per-IP budget; new attempts are counted as before.

### Security
- **Adding a passkey needs the phone.** `NewRelayHandler`'s `/passkey/register/options` used to hand out
  registration options to anyone holding your app's session, and a passkey approves requests on its
  own, so a stolen session cookie could become a permanent second factor. For a user with a linked
  phone the route now answers the same two-phase step as `/login` (202 with the number to show; the
  user approves a `PASSKEY_ENROLL` request on the phone) and returns the options only after that
  approval, once. Users without a linked phone are unchanged. The TouchQue API enforces this too:
  `WebAuthn.RegisterOptionsWithApproval` takes the approved request id as `approvalRequestID`.
- **Passkey delete needs the user.** The API now refuses `DELETE /webauthn/credentials/{id}` without
  `externalUsername`: use `DeleteCredentialForUser`; `DeleteCredential` is deprecated.

### Added
- The waiting step carries `TelemetryToken` when the workspace collects behavioural signals, so
  `@touchque/web` can send them (pass `telemetry: { apiBaseUrl }` to `touchqueFetch`). Before, the token
  never reached the browser and the bot and browser signals never ran for SDK integrations.

## [3.2.1] — 2026-10-11

### Security
- **The pre-auth relay no longer hands out a first-time linking QR.** `NewRelayHandler`'s `POST /login` used to answer
  an unlinked user with a linking QR code and recovery codes for whatever username was typed.
  Anyone could scan that QR first and link their own phone to someone else's account. Now it
  answers `{ state: 'enroll' }` without a QR unless `RelayOptions.LoginUser` is set, i.e. unless the route
  only runs after your own password step. Linking from a signed-in page (`/enroll/start`, the
  step-up guard) is unchanged. Your own guards can opt out with `GuardInput.NoEnroll`.

## [3.2.0] — 2026-10-11

### Added
- **`NewRelayHandler`** — a `net/http` handler serving every relay route a frontend needs
  (`POST /login`, enrollment, offline QR / codes, passkey sign-in, approval and management), with the
  same behaviour as the Node SDK's `touchqueRouter`. `RelayOptions.UserID` is required;
  `LoginUser` binds `/login` and the offline routes to your first factor (the offline routes are off
  without it unless `AllowOfflineWithoutFirstFactor` is set); pre-auth routes are rate limited per IP
  and per username by default (`RateLimitOptions`); `OnAuthenticated` runs once per sign-in with the
  user TouchQue reports, never one from the request body.
- `WebAuthnAuthenticateVerifyResponse` now carries `ExternalUsername` and `RequestID` when the API
  returns them.
- **`VerifyApprovalProof(proof, VerifyApprovalProofOptions)`** and `DetailsDigest` — check the phone's
  own signature over the request, action, number-match code and details it showed, without trusting
  TouchQue (same as the Node SDK's `verifyApprovalProof`). Pin the device key with `ExpectedPublicKey`;
  without it the check fails closed unless `AllowUnpinnedKey` is set. Tested against the cross-SDK
  golden vectors in `fixtures/approval-proof-vectors.json`.
- **`client.Login.ReportFraud(requestID, ReportFraudOptions{Reason, Note})`** — report a request you
  later learned was fraud (chargeback, account takeover, social engineering). TouchQue's risk engine
  uses it as its strongest training signal; the request's status does not change. Idempotent.

## [3.1.1] — 2026-10-10

### Security
- **`RequireOptions.User` is now required.** When it was nil, `Require` fell back to the
  client-supplied `X-Touchque-User` header, so on an integration that forgot to set `User` a
  caller could name any user and trigger that user's approval. `Require` now panics at wiring
  time without a `User` func. Resolve the user from your server-side session (or, for the login
  step, from whoever just passed your password check) — never from request input.

## [3.1.0] — 2026-09-30

### Security
- **A phone-side reject kills the offline QR.** `OfflineChallengeOptions.RequestID` and
  `VerifyTotpFor(..., requestID)` tie the QR / time-based code to the push it follows. Once the phone REJECTS the push,
  no new QR is issued for that sign-in (409 `request_rejected`) and no code — QR or time-based — finishes it
  (`Reason == "request_rejected"`). The guard links the QR
  automatically; while the QR is on screen the guard keeps checking the push, so the page learns about a reject
  straight away (`StepRejected`) — and about an approval, which finishes the action without typing a code.

### Added
- **Number matching on the offline QR.** When the linked push (or `RequireNumberMatch: true`) uses number
  matching, `Challenge()` returns `challengeCode` — print it under the QR. The phone shows it among two decoys
  after scanning and the user taps the match; the phone is never told which is right, so a wrong tap yields a code
  that fails verification. The guard's offline step carries it as `OfflineStep.ChallengeCode`.

## [3.0.0] — 2026-09-29

### Changed
- **Breaking:** the module path is now `github.com/Touchque/touchque-go/v3`, as Go
  requires for v2+ releases. Update imports to
  `github.com/Touchque/touchque-go/v3/touchque`.

### Security
- `Webhook.Verify` rejects a webhook whose signed `timestamp` is missing or
  unparseable (previously the freshness check was silently skipped).
- New `Webhook.VerifyWithOptions` with a `ReplayCache` (`NewMemoryReplayCache()`
  or your own `WebhookReplayCache` over Redis/DB): a second delivery of the
  same `jti` returns `*WebhookReplayError` — answer 200 to it, it is a duplicate.

## [2.0.0] — 2026-09-28

### Added
- `touchque.New()` reads `TQ_API_KEY` / `TQ_API_SECRET` / `TQ_API_URL` from
  the environment and returns an error instead of panicking; `NewClient`
  keeps its previous (panicking) behavior for existing callers.
- `client.Start` / `client.Check` / `client.Complete` — the headless step-up
  flow: start an approval, get back a `*Step` (the matching number, the
  enrollment QR, or a `StepBlocked`/`StepFrozen`/`StepRateLimited` refusal)
  to render in your own UI, and complete an approved request exactly once.
- `touchque.Require(client, action, next, RequireOptions)` — one line per
  protected `net/http` route, built on the same guard as every other SDK.
  The matching number is now available **before** approval (previously only
  `Login.RequestWithOptions`'s raw response carried it, with no framework
  support for relaying it to the browser, so number matching could not be
  completed through a one-line guard).
- `client.Offline` (`Challenge`, `Verify`, `VerifyTotp`) and `client.Actions`
  (`Define`, `List`) — previously only in the Node SDK.
- `*APIError` gains `Code` / `Reason` / `AttemptsLeft` / `RetryAfter`; a
  network failure now returns `*NetworkError` instead of an `*APIError` with
  `StatusCode: 0`.
- `*PasskeyRequiredError`, returned by `Login.Verify` when a
  phishing-resistant policy requires a passkey.
- `WebAuthn.DeleteCredentialForUser(id, externalUsername)` — scope a
  deletion to one user (previously any credential id your key could reach
  was deletable via `DeleteCredential`).
- `Login.Consume(requestID)` — uses an approved request exactly once.
- `GenerateSecretResponse.QRCodeDataURL` / `ResetSecretResponse.QRCodeDataURL`
  — the ready-to-render QR was previously silently dropped (the JSON field
  existed on the wire but had no matching struct field).

### Changed
- **Breaking:** default `BaseURL` is `https://api.touchque.com` (the
  previous default, `api-authenticator.touchque.com`, has no DNS record and
  was unreachable).
- **Breaking:** `Login.Verify` / `VerifyWithOptions` now return
  `*TimeoutError` (not `*RejectedError`) when a request expires unapproved,
  and populate `RequestID` / `ChallengeCode` / `Assurance` / `ConfirmedVia`
  on `VerifyResponse`.
- `LoginStatusResponse` gains `ExternalUsername`, `Type`, `ReferenceID`,
  `Details`, `Consumed`, `RequiresPasskey`, `ConfirmedVia`, `Assurance` (it
  previously parsed only `Status`).
- Request signing now covers the query string (`GET` with parameters) and
  uses a 16-byte nonce (previously 8).
- `Login.RequestWithOptions(LoginRequestOptions)` / `Login.VerifyWithOptions(opts, timeoutMs)`
  with `Details []LoginDetail`: transaction context shown on the mobile
  approval screen (e.g. `{Label: "Amount", Value: "1,250.00 USD"}`), in order.
  The API rejects out-of-limit values with a 400 (at most 8 entries, labels
  <= 40, values <= 120 characters) rather than truncating them.
  `Request` / `Verify` keep their positional signatures and delegate.

## [1.3.0] — 2026-09-06

### Changed
- **Module path fixed to the real location:**
  `github.com/Touchque/touchque-go` under its previous module path. The previous
  `github.com/touchque/touchque-authenticator-go` pointed at a repo that does
  not exist, so `go get` never worked. Install with
  `go get github.com/Touchque/touchque-go`; releases are the
  `touchque-go/vX.Y.Z` subdirectory tags. No code / API change — the package
  is still `touchque` and imports as
  `github.com/Touchque/touchque-go/touchque`.

### Added
- **`WebAuthn` resource** (parity with the Node SDK): `RegisterOptions`,
  `RegisterVerify`, `AuthenticateOptions`, `AuthenticateVerify`, `PrimaryOptions`,
  `PrimaryVerify`, `ListCredentials`, `DeleteCredential`. Server-to-server —
  the passkey ceremony runs in the browser (`@touchque/web` or
  `navigator.credentials.*`), your backend relays the JSON through these.
- **`Auth.GetUser(externalUsername)`** — user link status without sending a push.
- **`LoginRequestResponse.TelemetryToken`** — set when the integration has
  behavioral biometrics enabled; pass it to your frontend for the
  `@touchque/web` behavioral widget.
- `httpClient.delete()` for the new `DeleteCredential`.
- `Webhook.Verify` now takes an optional `toleranceSeconds` (parity; `0` disables
  the freshness check).

### Note
- Aligned to `v1.3.0` across the server SDK line (node / go / php / python).

## [1.1.0] — 2026-08-22

### Changed
- **Breaking:** module path renamed from `github.com/touchque/touchque-go`
  to `github.com/touchque/touchque-authenticator-go` to reflect that this
  SDK is scoped to the TouchQue Authenticator (2FA/MFA) product
  specifically.

### Fixed
- **Real bug:** `ApproveWithRecoveryCodeResponse.Success` was typed as
  `string`, but the real API returns `success` as a JSON boolean (matching
  the Node/Python/PHP SDKs). The old `.( string)` type assertion against a
  real boolean value always failed silently, leaving `Success` permanently
  at its zero value (`""`). Now typed as `bool`.
- README completely rewritten — the previous version documented a
  `client.RequestApproval()` method that does not exist anywhere in the
  source (the real equivalent is `client.Login.Verify(...)`), used an
  import path that didn't match `go.mod`, and claimed "E2E AES-256-GCM
  payload encryption" and "automatic exponential-backoff retry" features
  that were never implemented anywhere in this module.

### Added
- First real automated test suite (`go test`, 20 tests using
  `httptest.Server` for genuine HTTP round-trips covering `Config`
  sanitization, `httpClient` signing/error-handling, `Auth`, `Login`
  including its polling `Verify()`, and `Webhook`).
- `LICENSE` (MIT) file — the previous README/module had no license
  reference at all.

## [1.0.0] — prior to this changelog

Initial public functionality: `AuthResource` (GenerateSecret/ResetSecret/
ValidateSecret), `LoginResource` (Request/Status/Verify/
ApproveWithRecoveryCode), `WebhookResource` (Verify).
