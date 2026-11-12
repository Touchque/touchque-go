# Changelog

All notable changes to this project will be documented in this file. The
format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

Go modules are versioned via git tags (e.g. `touchque-go/v1.1.0`), not a
manifest field — the version below corresponds to the tag this SDK should
be released under next.

## [5.1.0] — 2026-11-12

### Fixed
- **`Require(nil, ...)` builds the client from the environment instead of failing.** A nil client panicked (nil pointer) on every request with a signed-in user. `Require` now builds it with `New()` (`TQ_API_KEY` / `TQ_API_SECRET` / `TQ_API_URL`) on the first request and keeps it once built. While it cannot be built, the route answers 500 `{"touchque": {"state": "blocked", "reason": "misconfigured"}, "error": {"code": "misconfigured", ...}}` with `Cache-Control: no-store` (401 `unauthenticated` when nobody is signed in), `next` never runs, and `[Touchque] TQ_API_KEY and TQ_API_SECRET are not set: routes guarded by Touchque answer 500 misconfigured.` goes to `RequireOptions.Logger` once per process. `Require` without `User` still panics (a wiring bug); `New()` and `NewClient` are unchanged. `RunGuard` with a nil client answers the same 500 instead of panicking.
- **The first-time QR stays on screen while it works.** Every poll with an `enroll` token started again (login request, 404, generate-secret 409, reset), so each poll replaced the QR and the recovery codes being scanned. The enroll step now carries `Enroll.ExpiresAt` (the API's `expiresAt` when it is ISO 8601, else now + `ttlMs`) and its token the claim `ee` (`GuardTokenClaims.Ee`). A poll with such a token reads the link state (`Auth.GetUser`): linked, it starts as before (`waiting` …); not linked and more than 15 seconds before the expiry, it answers 202 `{"touchque": {"state": "enroll", "expiresAt": ...}, "token": ...}` with no `enroll` and no other call, so the page keeps the QR and codes it shows; an expired QR (or a 404) gets a new one in `enroll.qrCodeDataUrl`. Another error of that check answers 503 `unavailable`. `IsStatusPoll` counts such polls while the QR is up (more than 15 seconds before its expiry), so the relay's per-user limit no longer refuses enrollment polls after a few seconds; the poll that renews an expiring QR, and a replayed old token, still count against it. Starts are always charged: `GuardInput.BeforeStart func() *GuardResult` is called at most once, right before a first-time-QR token starts something (a push once the phone is linked, or a new QR), and a result it returns is answered instead; the relay's `POST /login` charges its per-user `login` limit there, as for a fresh attempt, and answers its usual 429 when it is over (30 replays of an enroll token after linking gave 30 pushes on the poll budget). Pages on `@touchque/web` need 2.1.0.
- `IsStatusPoll(nil, ...)` answers false instead of panicking.
- **README code samples compile.** `Require` takes an `http.Handler`, so the examples wrap their handler functions in `http.HandlerFunc(...)`; the three primitives use the real signatures (`tq.Start(action, user, StartOptions{...})`, `tq.Check(requestID)`, `tq.Complete(requestID, user, action, CompleteExpect{...})`); the webhook example passes the body as a string.
- **go.mod says `go 1.26`**, not `go 1.26.3`, so `go get` no longer raises your project's go directive to a patch release.

### Added
- **`RequireOptions.ErrorBody func(GuardRefusal) any`: refusals in your app's own error shape.** Called for every answer with status 400 or above (never a 202 step) with a `GuardRefusal` (`Status`, `Code`, `Message`, `Touchque`, a copy of the step). What it returns counts by its JSON encoding: a value that encodes to an object (a map, a struct) is sent with `touchque` set to the step, anything else as it is; status and headers stay; a panic or a value that does not encode sends the default body and logs `[Touchque] ErrorBody failed`.
- **Refusals carry `X-Touchque-State` (and `X-Touchque-Reason` when the step has a reason)**, from `Require` and from the relay (`POST /login`, passkey registration), so `@touchque/web` 2.1.0 knows the state when an `ErrorBody` sends no `touchque`.
- `RequireOptions.Logger`: where `Require` logs its own lines (missing keys, a failed `ErrorBody`) and, with a nil client, those of the client it builds.
- `ResetSecretResponse.TTLMs` (`ttlMs` of `POST /auth/secret/reset`).
- README: "Guard inside your handler" (`RunGuard` after your own checks, the answers and headers to send, the 202 / enroll poll contract), "Refusals in your own error shape" and "Without API keys".

## [5.0.0] — 2026-11-11

### Breaking
- **Every name is spelled Touchque instead of TouchQue.** Code that uses an old name must be updated; nothing else changes (requests, JSON fields, event names, error codes, signatures and behaviour stay the same).
  - Module path of the public mirror: `github.com/Touchque/touchque-go/v4` → `github.com/Touchque/touchque-go/v5`; imports become `github.com/Touchque/touchque-go/v5/touchque`. The package is still `touchque` and the client still `touchque.Client` (`touchque.New()`, `touchque.NewClient`).
  - `(*MyAccount).UnlinkTouchQueApp` → `(*MyAccount).UnlinkTouchqueApp`.
  - Header constants: `GuardTokenHeader` `X-TouchQue-Token` → `X-Touchque-Token`, `GuardOfflineHeader` `X-TouchQue-Offline` → `X-Touchque-Offline`, `GuardCodeHeader` `X-TouchQue-Code` → `X-Touchque-Code`, `GuardCodeTypeHeader` `X-TouchQue-Code-Type` → `X-Touchque-Code-Type`, `GuardBrowserHeader` `X-TouchQue-Browser` → `X-Touchque-Browser`. HTTP header names are case-insensitive, so servers are unaffected (net/http already reads and writes them as `X-Touchque-*`).
  - Error and log texts: `*APIError` reads `Touchque API Error (HTTP …)` instead of `TouchQue API Error (HTTP …)`, the other errors start with `Touchque:` instead of `TouchQue:`, and log lines with `[Touchque …]` instead of `[TouchQue …]`. The error types (`APIError`, `NetworkError`, `TimeoutError`, `RejectedError`, `PasskeyRequiredError`, `ApprovalError`, `ApprovalMismatchError` …) keep their names: match them with `errors.As`, not by their text.

### Changed
- The README links work where the package is read (npm, PyPI, GitHub): the Actions and Touchque Login guides point to support.touchque.com, SECURITY.md and CONTRIBUTING.md to this package's public repository.
- The README has an "Action types" section: define a type once (dashboard → Developers → Action types, or from code); the guard answers 500 `misconfigured` for an undefined name and 403 `action_disabled` for one turned off.

## [4.2.0] — 2026-11-10

### Security
- **The offline approval-token check refuses another workspace's token.** `GET /agents/jwks.json` is one key set for every Touchque workspace, and the check used to compare `aud` only when you passed an audience, so a token Touchque signed for someone else's workspace (their own phone, any person's name, any details) could pass your executor. Now:
  - `Agents.VerifyApprovalToken(token, audience, expect)` (an empty audience) uses this workspace's own audience by default: `Agents.ApprovalAudience()` asks `GET /agents/approval-audience` once (`touchque:workspace:<id>`) and keeps it.
  - `VerifyApprovalTokenWith(token, jwks, audience, expect, now)` requires the audience. A missing or empty one throws *ApprovalMismatchError (`audience is required`).
  - A token without `aud` is refused (`the approval token names no workspace`), as is one for another workspace (`the approval token is for another workspace`).
  - Breaking for callers of the low-level function who passed no audience: pass Agents.ApprovalAudience()'s value.
  - `redeemApproval` was already safe: Touchque compares `aud` with your workspace there.

### Added
- **`DeviceRisk.SearchEvents(ctx, DeviceRiskSearchOptions{...})`: search your workspace's Device risk identifications**, newest first, one page at a time (`GET /device-risk/events`): `From`/`To` (7 days by default, at most 90, within your retention), `Signal`, `StepUp`, `Kind`, `Origin`, `IP` (an address or a CIDR range; never returned), `Account`, `VisitorID`, `RequestID`, `Limit` (1 to 100) and the opaque `Cursor` from the previous page's `NextCursor`.
- `DeviceRiskCheckResult.Engine`: the engine's state for this check; `"unavailable"` when the risk engine could not be reached and the verdict is a safe default (`StepUp` true), so an outage can be told apart from risk. Empty when the answer carries none.
- **`WebAuthn.PrimaryAvailability()`: is passkey sign-in on for your workspace?** `GET /webauthn/authenticate/primary/availability` answers a `WebAuthnPrimaryAvailability` (`Enabled`, `UserVerification` `required` or `preferred`, empty when off). Ask before your sign-in page shows its passkey button and passkey autofill; when it is off, `PrimaryOptions` answers 403 `passwordless_login_disabled`.

### Fixed
- **My Account step-ups can be satisfied.** `AuthorizationOptions.MaxAge` 0 still sends nothing, and a negative value now sends `max_age=0` (sign in again now); `CallbackChecks.MaxAge` and `VerifyIDToken`'s `maxAge` below 0 require a sign-in just now. The documented step-up (`MaxAge 0`) never sent `max_age`, so the hosted login reused the old session and the next My Account call failed again.
- **`SignAgentCard` works with any EC `crypto.Signer`.** An EC key that is not an `*ecdsa.PrivateKey` (a KMS, HSM, PKCS#11 or YubiKey signer) panicked; it is now signed through `Sign` and its DER answer turned into JWS `r || s`. A P-384 or P-521 key is refused (`malformed`) instead of being labelled ES256 with a signature no verifier accepts.
- **README Quick start no longer panics.** It used `touchque.NewClient(&touchque.Config{})`, which never reads the environment and panics on the empty API key; it now uses `touchque.New()`, which reads `TQ_API_KEY` / `TQ_API_SECRET`.

### Security
- **Hosted login: an empty `iss` is refused too (RFC 9207).** `HandleCallback` already refused a callback whose `iss` names another issuer; one with an empty `iss=` now returns `issuer_mismatch` as well, before the code is exchanged. A callback without `iss` (a server that does not send it yet) is still accepted.
- **Safe Guard: without a purpose, `VerifySafeApproval` accepts only an ordinary approval.** An empty `VerifySafeApprovalOptions.Purpose` used to try `approve` and then `schedule`, so a co-signer that executes on `Valid` would accept an approval meant to schedule a governance change, whose hash has no Safe nonce. `schedule` must now be named (`Purpose: "schedule"`); the shared vectors check it.
- **Touchque Login refuses a plaintext issuer.** `NewHostedLogin` now refuses an `http://` `Domain` except on this machine (`localhost`, `127.0.0.1`, `::1`, `*.localhost`), as the API `BaseURL` already did: codes, PKCE verifiers, the client secret and tokens would otherwise travel in clear text.

### Added
- **Shared Signals: receive the security events an identity provider sends after sign-in.** Touchque SSO sends Security Event Tokens (OpenID Shared Signals Framework 1.0) for an organization's members to the receivers its admin adds (Organization > Continuous access): CAEP `session-revoked`, `credential-change`, `device-compliance-change`, RISC `account-disabled`, `credential-compromise`; `txn` carries the case code of Touchque's decision. `NewSecurityEventVerifier(SecurityEventVerifierConfig{Issuer, Audience, JWKSURI?, JWKS?, ClockSkew?}).Verify(ctx, token)` returns a `*SecurityEvent` (`JTI`, `Issuer`, `Audience`, `IssuedAt`, `TXN`, `Subject`, `Type`, `Name`, `Claims`) or a `*SecurityEventError` with the RFC 8935 code to answer (`invalid_request`, `invalid_key`, `invalid_issuer`, `invalid_audience`); `PollSecurityEvents(ctx, PollSecurityEventsParams{URL, Token, Ack, SetErrs, MaxEvents})` for poll delivery (RFC 8936); `SecurityEventTypes`. The keys come from the issuer's `/.well-known/ssf-configuration`; a SET does not expire, so keep the jtis you handled. Tested against the shared vectors (`fixtures/security-event-vectors.json`).
- **Safe Guard: Safe transactions approved on the approver's phone, for TouchqueSafeGuard.** `client.SafeGuard.Request(ctx, SafeGuardRequestOptions{ExternalUsername, Type, SafeTx})` sends the raw transaction (the phone decodes it itself and signs with a key only its biometrics unlock), `Status(ctx, requestID)` and `WaitForApproval(ctx, requestID, timeout, pollInterval)` hand back the 105-byte approval. `VerifySafeApproval(target, approval, approverKey, VerifySafeApprovalOptions{Purpose, ApproverIndex, Rows | DisplayDigest, Now})` checks it the way the guard does, without trusting Touchque: the Safe transaction hash (EIP-712, Keccak-256 here) and the governance hash computed here, the 149-byte message, low `s`, the one-day expiry window, the P-256 signature. `WithSafeApprovals(ownerSignatures, approvals)` for `execTransaction`, `SafeScheduleCall(safe, governanceHash, approvals)` for a governance change; `SafeTxHash`, `SafeGovernanceHash`, `SafeApprovalMessage`, `SafeDisplayDigest`. Standard library only. Tested against the shared vectors (`fixtures/safe-guard-vectors.json`).
- **The headless step-up for any framework.** `RunGuard(ctx, client, GuardInput)` is the guard behind `Require` and the relay, for a framework without an adapter (gin, echo, chi …); `IsStatusPoll(client, GuardInput)` tells a request that only polls an approval already on its way (it never starts a push) from one your rate limit should count; `SignGuardToken(apiSecret, GuardTokenClaims)` / `VerifyGuardToken(apiSecret, token)` with the typed `GuardTokenClaims`, and `NormalizeDetails`. The same exports as the Node SDK.
- **`Login.WaitForApproval(ctx, requestID, timeout, pollInterval)`** polls a request you already sent until the user answers, like Node's `login.waitForApproval`: a `*VerifyResponse` once approved, a `*RejectedError`, a `*TimeoutError` (expired, or `timeout` ran out; 0 = 30 seconds) or a `*PasskeyRequiredError` (`Reason` `step_up`) when the Vishing Shield moved it to a passkey. `pollInterval` 0 is 400 ms; `ctx` stops the wait.
- **Webhook event constants for the Mobile SDK, Never Locked Out and the help desk**, the names the backend sends: `EventMobilePush`; `EventRecoveryStarted`, `EventRecoveryDeviceBound`, `EventRecoveryCooling`, `EventRecoveryCompleted`, `EventRecoveryVetoed`, `EventRecoveryExpired`, `EventRecoveryFailed`; `EventAssistOpened`, `EventAssistEnded`, `EventAssistCheckPassed`, `EventAssistCheckFailed`, `EventAssistUnfrozen`, `EventAssistClaimConfirmed`, `EventAssistClaimUnverified`.
- **Shared Signals: discovery and poll tests, and a README section** ("Shared Signals (security events from Touchque SSO)": verifying a pushed SET and polling). The tests run against a local stub, as in the Node SDK: keys found through `/.well-known/ssf-configuration` (metadata for another issuer is refused), and `PollSecurityEvents` sending the bearer token, `ack` and `maxEvents` and returning the transmitter's error code.

## [4.1.0] — not published (these changes ship in 4.2.0)

### Added
- **Device risk events like a device-intelligence event, without raw traits:** `deviceRisk.check` and `getEvent` answers carry `Network`, `Velocity` and `Bot`: the address as the risk engine saw it (country, region, city, never coordinates; the operator; `type` isp, hosting or tor; `timezoneMismatch` when the browser's clock does not fit the address), the visitor's counts (accounts, sign-ups, countries, stored-id resets, identifications in the last hour and day) and one answer to "a bot?" (`detected`, `suspected` or `not_detected`, with reasons). The field the script tag fills may now carry its pointer summary after the requestId: pass it as it came.

### Changed
- **Silent by default.** The SDK no longer writes to the standard `log` package: the guard's, relay's and `OnChallenge`'s problems go to `Config.Logger` (a `*slog.Logger`); nil, the default, logs nothing. Lines carry the error's type and text, never the request.
- `ApprovalMismatchError` no longer names the other person in its message.

### Added
- **A code typed back on the phone:** `LoginRequestOptions.Reply` (`LoginReplyRequest`), `LoginStatusResponse.Reply` (`LoginReply{CT, At}`), `NewCodeReplyKey()` and `OpenCodeReply(privateKey, requestID, ct)`.
- **Feature errors:** a feature your organization cannot use here (403 `feature_not_in_plan`, `feature_read_only`, `feature_off`) matches `errors.Is(err, ErrFeatureNotInPlan | ErrFeatureReadOnly | ErrFeatureOff)` (`ErrFeature` for any); `APIError.Feature` names it.
- **Webhook events `DEVICE_RISK_SIGNAL` and `DEVICE_RISK_ALERT`** (`EventDeviceRiskSignal`, `EventDeviceRiskAlert`): a Device risk signal that asks for more (identifiers, signals and the engine's verdict, never a trait), and an alert rule of the workspace that went off. Signed like every event.
- **Device risk in one line: `tq.DeviceRisk.Check(ctx, touchque.DeviceRiskCheckOptions{RequestID: req.FormValue("touchque_request_id"), ExternalUsername: email})`** with the script tag (`device.js`, `@touchque/web` 1.6.0), which fills that field. Pass it as it came: empty, made up or expired is still a verdict (`Report` missing, unknown, expired, invalid; the signal `device_identification_missing`, a number-matched step-up at most), never an error. `DeviceRiskReports`.
- **Device risk: `client.DeviceRisk.Check(ctx, DeviceRiskCheckOptions{RequestID: ...})` and `client.DeviceRisk.GetEvent(ctx, requestID)`** (a paid add-on; 409 `device_risk_off` until the workspace turns it on), and `DeviceRiskRequestID` (or `DeviceRisk`) in `LoginRequestOptions` and `RiskCheckOptions`. The page's requestId comes from `@touchque/web` `deviceRisk.identify`. Every signal only ever asks for more (`StepUp`, never a refusal); signals start in shadow. `ParseDeviceRiskCheck`, `DeviceRiskEvents`.
- **Pairing a browser by QR code: `client.QRPairings`.** `Create(ctx, CreateQRPairingOptions{KeyThumbprint, ClientIP, UserAgent, Browser, OS, TTLSeconds})` registers a pairing for the browser key your page holds (`@touchque/web` `browserKey.thumbprint()`) and returns `URI` (`touchque://pair-browser?...`) to show as a QR code; the nonce in it stays with you (Touchque keeps its hash). `Get` says who scanned it and how near the phone was (`Proximity`), `Refuse` tells the phone why your own checks said no. `LoginRequestOptions.QRPairing` asks the phone that scanned, once, with number matching. `QRPairingURI`, `QRPairingRefusalReasons`.
- **Touchque Login Management API:** `Identity.RotateClientSecret(clientID)` (the new secret is shown once), `Identity.Users.EndSession(userID, sessionID)` signs the person out of one session, `Identity.Exports.File(jobID)` returns the finished export (CSV or JSON lines) as text.
- **Actions: the `agent.approval` trigger**, before an AI agent's request reaches the phone (`Trigger: "agent.approval"`); only tightening counts: `api.deny`, `api.requirePasskey`, `api.stepUp`. See ACTIONS.md.
- **Webhook reason `user_blocked_agent`** (`ReasonUserBlockedAgent`): the person rejected an AI agent's request with Block this agent on their phone; the agent may not ask them again, and 2FA is not frozen. `ListBlocks` can return the block reason `"phone"`.
- **AI agents: events for a SIEM.** `Agents.ListEvents(AgentEventOptions{After, Since, Limit})`: the workspace's agent events (`AGENT_*`, `AGENTS_*`) oldest first, each with its agent, person, approval and case code; keep `Next` and pass it as `After`.
- **AI agents: the workspace's policy and a passkey line.** `Agents.GetWorkspacePolicy()` / `SetWorkspacePolicy(policy)`: every agent's floor (an agent's own policy can only be stricter, field by field). `AgentPolicy.RequirePasskeyAbove`: over it the person approves with a passkey on your page (`AgentApprovalState.RequiresPasskey`), never on the phone or with a mandate; a background request gets 409 `interactive_required`. `EventAgentWorkspacePolicyChanged`. A second approver who answers sooner than a person can gets no token (status `blocked`, reason `inhuman_approval`).
- **Touchque Login: the approving app's name and custom-domain-only sign-in.** `Identity.SetApproverAppName(&name)`: the phone app the hosted pages tell customers to approve on ("Approve on the Acme app"; `nil` = your brand when the Mobile SDK is set up, else Touchque). `Identity.SetCustomDomainOnly(true)`: serve sign-in only on the primary custom domain ({slug}.login.touchque.com redirects page loads there and refuses other calls; needs a verified primary domain with a working certificate). `Identity.CheckDomainCertificate(domainID)`: the domain's certificate at the sign-in edge now (`certificate`: pending, active or error).
- **Cross App Access (ID-JAG) and A2A agent cards.** `RequestIDJAG` trades a member's ID token for an ID-JAG at the organization's identity provider, `RedeemIDJAG` trades it for an access token at the other service (jwt-bearer); `IDJAGVerifier` checks one at your own authorization server (typ, issuer, single audience, client, expiry, used once; `FirstUse` for a shared store). `VerifyAgentCard` checks an A2A card's signatures (JWS over the RFC 8785 canonical card; `jku` only on the card's host or `TrustedJKUHosts`), `SignAgentCard`, `CanonicalJSON`.
- **Security-change lock, look-alike destinations, Second Thought questions — for any action type.** `LoginRequestOptions.SecurityChanges` (`&SecurityChanges{Password, MFA, Device, Email, Phone}`, when each last changed in your system): access rules and Actions read `minutesSince.mfaChange`, `.deviceChange`, … (e.g. refuse `PAYOUT_CHANGE` within 24 h of a 2FA change). `Destination` (`&Destination{Kind: "iban", Value, Known}`; kinds iban, account, wallet, address, payee) is shown in full on the phone in groups of four, with a warning when it looks like one the user used before but is not the same; `LoginRequestResponse.Destination` is a `DestinationCheck{Known, Lookalike}`, rules read `destination.lookalike`. `Locale` ("tr" | "en") for those rows. `DefineOptions.SecondThought` (`&SecondThought{Questions, Locale}`, at most two of `SecondThoughtQuestions`; one without questions turns them off): the phone asks them before Approve and a risky answer makes the approval provisional.
- **Mobile SDK: your own app approves for your users.** `Mobile.CreateEnrollment(CreateMobileEnrollmentOptions{ExternalUsername, Replace, TTLSeconds})` gives a one-time `tqe_` token your iOS/Android app spends with the Touchque Mobile SDK; `ListDevices`, `GetDevice`, `RemoveDevice`, `Settings`, `UpdateSettings`. `MobilePushFromWebhook(event)` turns the signed `MOBILE_PUSH` webhook into the APNs payload / FCM data you send with your own keys; `(*MobilePush).Expired`.
- **Mobile SDK: Touchque can send the push.** `UpdateSettings` takes `apns` / `fcm` (your own APNs key / Firebase service account); Touchque then pushes that platform itself instead of the `MOBILE_PUSH` webhook (nil removes a key). `MobileSDKSettings.Push` shows who pushes, never the keys. `UpdateSettings` takes `androidCerts` (the SHA-256 of each Android app's signing certificate, checked against Key Attestation at enrollment). `Mobile.TestPush(deviceID)` sends a harmless push the way a request would reach the phone and says which way it went and whether APNs / FCM took it; a `MOBILE_PUSH` webhook may now have kind `test`.
- **`ClientSignals` on `LoginRequestOptions` and `RiskCheckOptions`:** the end user's page check from `@touchque/web`; a browser driven by software is never silent and asks with number matching, or is refused where the workspace blocks it.
- **Help desk.** `Assist.Open(ctx, OpenAssistOptions{ExternalUsername, Agent: AssistAgent{Name, Title, Ref}, Reason})` before your help desk acts on someone's account (their phone gets a calm notice; their "someone says they're from IT" button shows the agent), `Verify(ctx, id, VerifyAssistOptions{Action})` before a sensitive action (a 2-digit `ChallengeCode` the agent reads to the person, who types it and approves on their phone; `no_phone` routes to Never Locked Out), `Spend` right before the action, `Unfreeze`, `Get`, `List`, `End`; `(*AssistSession).CheckPassed(requestID)`. Webhooks `ASSIST_*`, among them `ASSIST_CLAIM_UNVERIFIED` (someone pretended to be IT).
- **Touchque Login: an app acting for a customer.** `login.ExchangeToken` (RFC 8693), `login.AskUser(ctx, AskUserParams{...})` and `login.WaitForUser(ctx, ask)` (CIBA, poll mode); `TokenSet.AuthorizationDetails`, `IssuedTokenType`.
- **Touchque Login: token vault.** `(*HostedLogin).GetConnectionToken(ctx, userAccessToken, connection, scope)` returns the provider's own access token (Google, Microsoft, GitHub…) for the signed-in customer from a connection that stores tokens (`options.tokenVault`); Touchque refreshes it and the refresh token never leaves (`TokenSet.Connection`, `ConnectionTokenType`). `IdentityUsers.ConnectedAccounts` and `DisconnectAccount`; `(*MyAccount).StopAppAccess` and `identities[].appAccess`.
- **`LoginRequestOptions.ExpiresIn`:** how long the push waits for the person, 30 (default) to 300 seconds, for requests the person has to read first (an AI agent asking on their behalf).
- **`McpAuth` for MCP servers whose authorization server is Touchque SSO** (Organization → MCP servers). `NewMcpAuth(McpAuthConfig{Issuer, Resource, Tools})`:
  `ProtectedResourceMetadata` at `MetadataPaths` (RFC 9728), `Verify(r)` (Touchque's JWKS, issuer, audience = this server, expiry,
  DPoP proof for a bound token), `RequireTool` (403 `insufficient_scope` with the scope), `Middleware` (`McpClaimsFrom(ctx)`),
  `WriteMcpAuthError`. `*McpAuthError` carries the status and the `WWW-Authenticate` header.
- **Attack protection in `client.Identity`:** `GetAttackProtection`, `SetAttackProtection`, `AttackEvents`.
  Actions accept the Touchque Login triggers (`identity.post_login`, …).
- **Email and SMS providers in `client.Identity`:** `GetDelivery`, `SetDelivery`, `RemoveDelivery`, `TestDelivery`.
  **My Account:** `StartSMSEnrollment`, `VerifySMSEnrollment`, `RemoveSMSCodes`.
- **Touchque Login My Account API.** `login.MyAccountToken(ctx, refreshToken, scope)` trades a first-party app's
  refresh token for a `https://<domain>/me/` token (keep the rotated refresh token); `login.MyAccount(accessToken)`
  returns `*MyAccount` (Get, UpdateProfile, AuthenticationMethods, RemovePasskey, UnlinkTouchqueApp, SetEmailCodes,
  UnlinkIdentity, SetPassword, RemovePassword, ChangeEmail, Sessions, EndSession, EndOtherSessions, Apps, RevokeApp,
  Consents, SetMarketing, ExportData, DeleteAccount). A too-old sign-in returns `*MyAccountError` with `StepUp()`
  true. `login.AccountURL(section)` links the hosted account page.
- **Touchque Login Management API: `client.Identity`.** `Users` (List, Get, Create, Update, Block, Unblock,
  Delete (KVKK/GDPR erasure), Export, Sessions, SignOutEverywhere, ResetMFA, UnlinkIdentity,
  SendVerificationEmail, PasswordReset, AddRoles, RemoveRole, Logs), `Imports` and `Exports` (Start, Get, Wait),
  `Roles`, `Organizations` (Members, AddMembers, RemoveMember, SetConnections, Invite, RevokeInvitation),
  `Clients`, `APIs`, `Connections`, `CustomDomains`, and the tenant (GetTenant, UpdateTenant, RotateSigningKey,
  Outbox).
- **Touchque Login (hosted sign-in) for your app.** `NewHostedLogin(HostedLoginConfig{...})` is an OpenID Connect
  client for your tenant (`acme.login.touchque.com` or your own domain): `AuthorizationURL` (PKCE S256, state,
  nonce, `ScreenHint`, `LoginHint`, `UILocales`, `Connection`, `Organization`, `MaxAge`, `ACRValues`),
  `HandleCallback` (state and `iss` checks, code exchange, ID token verified against the JWKS: signature, issuer,
  audience, expiry, nonce, `at_hash`), `Refresh`, `ClientCredentials`, `Revoke`, `Userinfo`, `LogoutURL`, and
  `VerifyAccessToken(ctx, token, audience, scopes...)` for your API. Standard library only.
- **AI agents as identities of their own.** `client.Agents` registers an agent with its PUBLIC key, an accountable
  owner, the action types it may ask approvals for and a review date (`Create`, `List`, `Get`, `Update`, `AddKey`,
  `RemoveKey`, `Suspend`, `Resume`, `Revoke`, `SetKillSwitch`). `NewAgent(AgentConfig{...})` is the agent side: its
  own key (private_key_jwt, RFC 7523), a 10-minute token bound to that key with DPoP (RFC 9449), never your API key.
  `GenerateAgentKey("ES256" | "EdDSA")`, `JWKThumbprint()`.
- **Agent policies and people who stopped an agent:** `client.Agents.SetPolicy(id, AgentPolicy{...})`, `ListBlocks(id)`, `LiftBlock(id, user)`.
- **Agents ask people to approve on their phone.** `agent.RequestApproval(AgentApprovalParams{...})`,
  `agent.WaitForApproval(ctx, id, timeout, interval)` (approval token or `*ApprovalError`),
  `client.Agents.RedeemApproval(token, ApprovalExpectation{...})` (checked before anything is used, then used exactly
  once; `*ApprovalMismatchError`), `client.Agents.VerifyApprovalToken()` and `VerifyApprovalTokenWith()` offline,
  `MatchesAuthorizationDetails()`.
- **Four eyes and mandates.** `AgentPolicy.FourEyes` (a second approver on their phone; `awaiting_second` keeps
  `WaitForApproval` waiting; `SecondApprover`, `SecondChallengeCode`). `agent.RequestMandate(MandateParams{...})`,
  `GetMandate`, `RevokeMandate`; `AgentApprovalParams.MandateID` is approved within the mandate without a push.
  `client.Agents.ListMandates(id, user)`, `RevokeMandate(id, mandateID)`.
- **What Touchque notices about an agent.** Refusals carry the case code; new codes `suspicious_content` (400, `markers`),
  `interactive_required` (409), `name_too_similar` (409 on create/update, `similarTo`); an approval answered faster than a
  person ends `blocked` with reason `inhuman_approval`. `EventAgent*` constants name every agent event.
- **Organization AI agents on Touchque SSO: `NewOrgAgent(OrgAgentConfig{...})`.** DPoP-bound tokens for one of the
  organization's apps with its own key or its platform's token (`GitHubActionsToken("touchque")`, `FileToken(path)`):
  `GetToken(resource, scope)`, `Authorize(req, resource, scope)`, `DPoPProof()`.
- **An organization's agent acts for a member.** `ExchangeToken(subjectToken, resource, scope)` (RFC 8693),
  `AskMember(AskMemberParams{...})` and `WaitForMember(ctx, request)` (CIBA, poll mode).
- **An organization's agent uses a member's own account elsewhere (token vault).** `(*OrgAgent).GetConnectionToken(subjectToken, connection, scope)` returns an `OrgAgentConnectionToken`: the member's own access token at Google, Microsoft 365, GitHub, Slack, Salesforce or any OAuth 2.0 service they connected on Touchque (portal `/connections`), for a connection that names the agent. A Bearer token for that service; Touchque refreshes it and the refresh token never leaves; `invalid_grant` when the member has not connected it, disconnected or left.
- **An organization's agent asks for a shared account.** `(*OrgAgent).AskToOpenSharedAccount(account, loginHint, message)` → `SharedAccountAsk{AskID, OpenURL, Status, ExpiresIn}`: the member opens `OpenURL` where their Touchque extension is paired, their phone approves with the agent named, and the extension signs in there; the agent never sees the password. `SharedAccountAskStatus(askID)` and `WaitForSharedAccount(ctx, ask)` say only how it ended (`opened`, `refused` with a reason, `declined`, `expired`).
- **Token vault for your agents (`Agents.Vault`).** `PutConnection(name, AgentVaultConnectionParams{Provider, ClientID, ClientSecret, Tenant, Issuer, AgentIDs})` (google, microsoft, github, facebook, linkedin, x, oidc: your OAuth app there), `Deposit(connection, user, AgentVaultDeposit{...})` after your own OAuth flow with the person, `ListConnections`, `ListAccounts(user)` (never a token), `RemoveAccount`, `RemoveConnection`. The agent: `(*Agent).GetConnectionToken(user, connection, scope)` (scope `vault:read`): a fresh Bearer token for that service, refreshed by Touchque; the refresh token never leaves.
- **`(*Agent).RequireApproval(ctx, params, onChallenge, timeout)`:** asks the person's phone and waits in one call (the number shown through `onChallenge`), for putting in front of any agent framework's tool call.
- **API key scopes are enforced:** a narrower key (for example `login:*`) is refused elsewhere with 403 `insufficient_scope`.
- **`Device`** on `GetUserResponse` (`*DevicePosture`): the linked phone's posture (platform, model, OS version,
  security patch, screen lock, jailbreak/root, hardware key, attestation, `State`, `Issues`), or nil before a phone is linked.
- **`RadiusClient`** (`NewRadiusClient`, `Config`, `Authenticate`, `Wait`, `Passcode`): the RADIUS API of
  Touchque SSO, for the Touchque RADIUS proxy and anyone building their own RADIUS server. VPN sign-ins
  with the number shown on the VPN, a plain push, or a code from the Touchque app; `DefaultSSOBaseURL`.
  For a Touchque outage: `OutageCache` (signed pages of everyone who may use the VPN with digests of their
  next codes), `OpenOutagePage` (checks the signature), `MatchOutageCode`, `OutageLog` (what was decided
  meanwhile), and `RadiusApp.OutagePolicy`.
- **`ChallengeDigits`** in `LoginRequestOptions` (`2` or `3`): the length of the matching number when one is
  shown, `3` for 100–999. The longer of this and your workspace policy wins: a request can lengthen the
  number, never shorten it.
- **Codes during a Touchque outage:** `Offline.TotpVerifiers` and `MatchTotpVerifier`. While Touchque answers,
  fetch salted, slow digests of your users' next time-based codes (up to 4 hours ahead, 24,000 user-steps a
  call; never a key); while it cannot be reached, check a typed code against them locally. Needs the workspace policies
  `offlineTotpEnabled` and `outageVerifiersEnabled`; frozen and removed users fall out on the next fetch.

## [4.0.0] — 2026-10-20 — Touchque Actions

> 3.6.0 (Never Locked Out) and 3.7.0 ("Why?" case codes) below were not published on their own; they ship in 4.0.0.

### Breaking
- **Module path `github.com/Touchque/touchque-go/v4`.**
- **Action types moved to `Client.ActionTypes`** (`*ActionTypesResource`: `Define`, `List`).
  `Client.Actions` is now Touchque Actions. Replace `client.Actions.Define(...)` with
  `client.ActionTypes.Define(...)`.

### Added
- **Touchque Actions** (`Client.Actions`): your own code at points of the approval pipeline, run by Touchque
  in a sandbox. See [ACTIONS.md](../ACTIONS.md).
  - `Deploy(slug, DeployActionOptions{Trigger, Code | Template, Secrets, AllowedHosts, Capabilities,
    OnFailure, Order, Enabled, Activate})` (idempotent; a version asking for a loosening capability answers
    `Deployed: false` with `Approval.Required` and waits for an admin's phone approval), `List`, `Get`,
    `Version`, `Update`, `Delete`, `Rollback(slug, *int)`.
  - Developer loop: `Test(TestActionOptions{…, EventID | Event})` (one run, nothing sent),
    `DryRun(DryRunActionOptions{…, Replaces, Limit, Since})` (replay against recent real decisions),
    `Events`, `Logs`, `Metrics`.
  - `Triggers()`, `Templates()`, `RenderTemplate(id, trigger, params)`; `Actions.Secrets.Set | List | Delete`.
- `Context map[string]interface{}` on `LoginRequestOptions`, `RiskCheckOptions`, `StartOptions`,
  `GuardInput`, and `RequireOptions.Context func(*http.Request) map[string]interface{}`: for your Actions only
  (`event.context`), never shown on the phone.
- **`OnChallenge func(VerifyChallenge)` on `LoginRequestOptions`** (used by `Login.VerifyWithOptions`): with number
  matching the phone asks for a number that the call used to return only after the approval. `OnChallenge` runs
  once, right after the request is created and before the wait, with `VerifyChallenge{RequestID, ChallengeCode,
  ExpiresAt, Reasons, CaseCode}`. Show `ChallengeCode` to the user now; the phone asks for it. Not called when only
  a passkey can approve. A panic in it is recovered and logged: the call keeps waiting.
- `RiskReason.Action`: with `Code: "action"`, the slug of the Action that asked.
- **Passkey autofill** (WebAuthn conditional mediation): `WebAuthn.PrimaryOptions("")` asks for options
  that accept any passkey of your site, and `PrimaryVerify` names the user the passkey belongs to.
  `NewRelayHandler`'s `POST /passkey/authenticate/options` does the same when the body has no `email`, so
  `@touchque/web`'s `passkeys.autofill()` works with no extra route.

## [3.7.0] — 2026-10-19 — "Why?" case codes

### Added
- **Case codes.** Every approval decision (`Login.Request`, `Risk.Check`) now names a short case code
  (`K7P-2QX`). Show it to your user ("Tell your support team: K7P-2QX"); your team opens the decision by it in
  the dashboard (Logs → Look up a case).
  - `LoginRequestResponse.CaseCode` and `Reasons` (why number matching or a passkey is needed; plain English,
    never a score).
  - `RiskCheckResult.CaseCode`.
  - `APIError.CaseCode` on refusals (blocked, frozen, rate limited, provisional, keys lost).
  - `Step.CaseCode` and `Step.Reasons` (`Start`, the guard, the relay and the HTTP middleware); the guard keeps
    showing the code while it waits.

## [3.6.0] — 2026-10-19 — Never Locked Out

### Added
- **Never Locked Out.** A user whose phone is lost, dead or replaced moves to a new phone without a help desk:
  colleagues they named vouch on their own phones, then a cooling-off anyone can veto.
  - `tq.Recovery.SetVouchers(ctx, user, vouchers)` and `tq.Recovery.Vouchers(ctx, user)` (who can vouch today and why
    not). Ask for the user's phone before you change the list.
  - `tq.Recovery.Start(ctx, StartRecoveryOptions{...})` returns a `*Recovery` with `BindURI` (show it as a QR for the
    new phone); `Status(ctx, id)`, `List(ctx, user, open)`, `Veto(ctx, id, by, reason)`, `(*Recovery).Open()`.
  Only after your first factor (password, IdP). The risk engine's BLOCK refuses; hard signals add a voucher and
  double the cooling-off. Errors carry `code`: `not_enough_vouchers` (with `required`, `eligible`, `vouchers`),
  `recovery_in_progress`, `blocked`, `frozen`, `rate_limited`, `device_not_linked`. After a vouch move, critical
  actions answer 403 `blocked` / `recovery_probation` for 24 h. New webhook events `RECOVERY_STARTED`,
  `RECOVERY_DEVICE_BOUND`, `RECOVERY_COOLING`, `RECOVERY_COMPLETED`, `RECOVERY_VETOED`, `RECOVERY_EXPIRED`,
  `RECOVERY_FAILED`; `DEVICE_LINKED` can carry `via: 'recovery'`.
- `details` / `noticeDetails` on start: what the vouchers' phones and the old phone show, in your words (default
  English lines otherwise).
- Approval requests on the phone carry `expiresAt` (a vouch stays open for 10 minutes).

### Changed
- Phone-to-phone transfers must be signed by a phone with a hardware key (the apps do since this release) and move
  only the accounts the phone chose.
## [3.5.0] — 2026-10-18 — Silent sign-ins

### Added
- **Silent sign-ins.** Stop asking the phone again and again when nothing about a sign-in is new. Touchque's
  risk engine decides; the push is skipped only when it says so.
  - `tq.Risk.Check(ctx, RiskCheckOptions{ExternalUsername, Type, ClientIP, UserAgent, BrowserProof, MaxAgeSeconds})` →
    `*RiskCheckResult{Prompt, Reasons, Assurance, SilentMode}` (`RiskReason{Code, Text}`). Sends nothing to the
    phone. Read fail-closed: `Prompt` is `false` only when the API answered the boolean `false`; malformed
    `reasons` become `[]`, a missing or unknown `assurance` is `"normal"`. `MaxAgeSeconds` is a `*int` so `0`
    (always ask) can be sent.
  - `tq.Risk.Browsers(ctx, RiskBrowsersOptions{ExternalUsername})` and
    `tq.Risk.ForgetBrowsers(ctx, ForgetBrowsersOptions{ExternalUsername, Thumbprint})`: the browsers Touchque knows
    for a user, and forgetting one (`Thumbprint`) or all of them.
  - `LoginRequestOptions.BrowserProof` and `StartOptions.BrowserProof`: the browser's device-bound key proof
    (`X-Touchque-Browser`, made by `@touchque/web` 1.4.0), passed through untouched; once the request is approved,
    Touchque knows that browser.
  - `SilentSignIn` option (default off) on `RequireOptions`, `RelayOptions` (POST /login) and `GuardInput` (with
    `GuardInput.BrowserProof`): a new attempt carrying the `X-Touchque-Browser` header is checked first;
    `prompt: false` approves it at once with no push (`Assurance.Method == "silent"`, `ConfirmedVia == "SILENT"`,
    `RequestID == "silent"`, `Approval.Reasons`; the relay's `OnAuthenticated` gets `Via == ViaSilent`). Otherwise,
    and on any error in the check, the usual push starts with the proof attached. `SilentSignInMaxAgeSeconds` sets
    your own limit on the age of the last phone approval. Polling with the token never checks again.
  - `GuardBrowserHeader` (`X-Touchque-Browser`), `ViaSilent`.
- `Require` and the relay's POST /login pass the incoming request's context to the silent check.

## [3.4.0] — 2026-10-18

### Added
- **Vishing Shield.** When the user taps Approve during a call (or with the screen shared or the phone
  remote-controlled), Touchque can move the request to a passkey, refuse it, or approve it as provisional.
  `Approval`, `LoginStatusResponse`, `ConsumeResponse` (embedded `ShieldFields`) and `VerifyResponse.Provisional` carry `provisional`, `revoked`, `revokeReason` and
  `reconfirmedAt`: a provisional approval lets the user in, but Touchque refuses their critical actions
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
  offline code Touchque refuses for that reason answers `passkey_required` instead of `blocked`.
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
  approval, once. Users without a linked phone are unchanged. The Touchque API enforces this too:
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
  user Touchque reports, never one from the request body.
- `WebAuthnAuthenticateVerifyResponse` now carries `ExternalUsername` and `RequestID` when the API
  returns them.
- **`VerifyApprovalProof(proof, VerifyApprovalProofOptions)`** and `DetailsDigest` — check the phone's
  own signature over the request, action, number-match code and details it showed, without trusting
  Touchque (same as the Node SDK's `verifyApprovalProof`). Pin the device key with `ExpectedPublicKey`;
  without it the check fails closed unless `AllowUnpinnedKey` is set. Tested against the cross-SDK
  golden vectors in `fixtures/approval-proof-vectors.json`.
- **`client.Login.ReportFraud(requestID, ReportFraudOptions{Reason, Note})`** — report a request you
  later learned was fraud (chargeback, account takeover, social engineering). Touchque's risk engine
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
  SDK is scoped to the Touchque Authenticator (2FA/MFA) product
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
