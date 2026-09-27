# Changelog

All notable changes to this project will be documented in this file. The
format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

Go modules are versioned via git tags (e.g. `touchque-go/v1.1.0`), not a
manifest field — the version below corresponds to the tag this SDK should
be released under next.

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
