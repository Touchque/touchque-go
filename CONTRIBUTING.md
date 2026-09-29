# Contributing

Thanks for considering a contribution to `github.com/Touchque/touchque-go/v3`.

## Setup

```bash
go build ./...
```

## Running tests

```bash
go test ./...
```

Some suites run **contract tests** against `testing/fake-touchque-api.mjs` — a
small, dependency-free Node server that verifies the SDK's HMAC request
signatures exactly like the real API does. These need `node` on `PATH`; they
skip themselves otherwise.

## Making a change

1. If it touches the wire protocol or the step-up contract, update the
   fixtures in `fixtures/` and the fake API in `testing/` first.
2. Add tests. A behavior change without a test won't be merged.
3. Update `CHANGELOG.md` (Keep a Changelog format) under `## [Unreleased]`.
4. Keep code, comments, docs and error messages in English.
5. Keep `go vet ./...` and `gofmt -l .` clean.

## Pull requests

- Describe what changed and why, not just what. If it's a breaking change,
  say so explicitly and explain the migration.
- CI must pass.

## Reporting a security issue

Please don't open a public issue — see [SECURITY.md](./SECURITY.md).
