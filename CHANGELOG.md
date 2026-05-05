# Changelog

All notable changes to this project will be documented in this file.

This format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and versioning follows [Semantic Versioning](https://semver.org/).

## [Unreleased]

## [0.2.0] - 2026-05-05

### Added

- First-run setup wizard ([#12](https://github.com/scottlz0310/mcp-gateway/issues/12))
  - If `GITHUB_MCP_CLIENT_ID`, `GITHUB_MCP_CLIENT_SECRET`, or routes are missing on startup, the gateway enters **setup mode** automatically instead of exiting
  - `GET /setup?token=<TOKEN>` returns the list of missing configuration fields as JSON
  - `POST /setup?token=<TOKEN>` accepts `{client_id, client_secret, routes[]}`, encrypts the secret via `age`, writes `config.yaml`, and exits with code `0` for supervisor-based restart
  - Setup token is 16 bytes / 32 hex chars, single-use, with a 15-minute TTL
  - All non-`/setup` paths return `503 {"error":"setup_required","setup_url":"..."}` during setup mode
  - `internal/setup` package: `Manager` (token lifecycle), `IsSetupRequired` (effective-config sufficiency check), `Handler` (GET/POST endpoints), `UnconfiguredHandler` (503 fallback)
  - `AppConfig` extended with `Routes []RouteConfig` and `Setup SetupConfig` fields (YAML: `routes:`, `setup:`)
  - `router.ParseFromConfig` added: converts `[]config.RouteConfig` → `[]Route` with the same validation rules as `ParseEnv` (env `ROUTE_*` takes precedence; config.yaml routes are used as fallback)
  - Normal startup now falls back to `config.yaml` routes when no `ROUTE_*` env vars are set

- Secret encryption at rest via `filippo.io/age` X25519 ([#11](https://github.com/scottlz0310/mcp-gateway/issues/11))
  - `GITHUB_MCP_CLIENT_SECRET` can now be stored as `ENC[age:]<base64>` in `config.yaml` instead of as a plain env var
  - `internal/config` package: `LoadKey`, `EncryptField`, `DecryptField`, `MigrateSecret`, `LoadConfig`, `SaveConfig`
  - Key file (`gateway.key`) uses the standard `age-keygen` identity format (`AGE-SECRET-KEY-1...`), compatible with `age` CLI
  - Key generation priority: existing `gateway.key` > HKDF-SHA256 derivation from `MCP_GATEWAY_MASTER_KEY` > random generation
  - Migration on startup: `ENC[age:]` in config → decrypt; plaintext in config → encrypt+rewrite; `GITHUB_MCP_CLIENT_SECRET` env → encrypt+save; absent → fatal error
  - Corrupt/empty/unreadable `gateway.key` causes a hard stop — no auto-regeneration (prevents permanent loss of encrypted secrets)
  - `MCP_GATEWAY_MASTER_KEY` requires ≥ 32 bytes; `MCP_MASTER_KEY` accepted as a legacy alias
  - Key contents, plaintext secret, `ENC[...]` ciphertext, and env var values are never written to logs

- Device Flow per-device polling serialization ([#16](https://github.com/scottlz0310/mcp-gateway/issues/16))
  - `AcquireDevicePolling` / `ReleaseDevicePolling` added to `internal/auth.Store` to serialize concurrent GitHub polling per `device_code`
  - Concurrent requests presenting the same `device_code` while one is already polling GitHub receive `authorization_pending` immediately, preventing `slow_down` / rate-limit responses from GitHub (RFC 8628 §3.5)

- v0.1.0 acceptance E2E runbook ([`docs/runbook-e2e-v0.1.0.md`](docs/runbook-e2e-v0.1.0.md))
  - 11 ordered scenarios: first-run setup wizard → config-encryption round trip across restarts → `gateway.key` corruption refusal → `MCP_GATEWAY_MASTER_KEY` deterministic derivation → Authorization Code + PKCE → longest-prefix routing with `X-Authenticated-User` injection → `refresh_token` grant rotation → persistent token store re-auth skip → Device Authorization Grant under concurrent polling → per-route `auth=none` bypass → RFC 6750 / RFC 9728 `WWW-Authenticate` semantics
  - Each scenario carries explicit expected behavior, an observed-behavior worksheet slot, a result summary table, an issue template for failures, and cleanup recipes for partial reruns
  - Serves as the v0.2.0 release gate

### Changed

- `tasks.md` synced with v0.1.0 implementation reality
  - #11 Config Persistence ([PR #37](https://github.com/scottlz0310/mcp-gateway/pull/37)) and #12 Setup Wizard ([PR #38](https://github.com/scottlz0310/mcp-gateway/pull/38)) marked complete; all subtasks reconciled to `[x]`
  - "Recommended order" header rewritten to a "v0.1.0 released" view
  - **v0.2.0 roadmap** added (RM1〜RM6): RM1 v0.1.0 E2E acceptance (release gate) · RM2 observability baseline · RM3 CI hardening (coverage, golangci-lint, govulncheck) · RM4 documentation restructuring · RM5 deferred-issue triage (#3/#4/#5/#6) · RM6 v0.2.0 release. Per-RM issue creation is intentionally deferred to immediately before each item is started.

### Fixed

- Device Authorization Grant polling now enforces the provider interval after each GitHub poll, so fast follow-up requests for the same `device_code` are answered locally with `authorization_pending` instead of reaching GitHub and producing `slow_down`.

## [0.1.0] - 2026-04-30

### Added

- Device Authorization Grant (RFC 8628) implementation ([#10](https://github.com/scottlz0310/mcp-gateway/issues/10))
  - `POST /device_authorization` endpoint: gateway initiates GitHub Device Flow and returns `user_code` and `verification_uri` to the client
  - `POST /token` extended to dispatch by `grant_type` (`authorization_code` / `urn:ietf:params:oauth:grant-type:device_code`)
  - `/.well-known/oauth-authorization-server` now includes `device_authorization_endpoint` and `urn:ietf:params:oauth:grant-type:device_code` in supported `grant_types`
  - Added `DeviceSession` management to `internal/auth.Store` (CreateDevice / GetDevice / AuthorizeAndConsumeDevice / DenyDevice)
  - `AuthorizeAndConsumeDevice` eliminates TOCTOU races: token recording and session deletion are atomic under a single lock
- Per-route authentication bypass: append `|auth=none` to a `ROUTE_*` value to opt individual routes out of Bearer validation ([#22](https://github.com/scottlz0310/mcp-gateway/issues/22), [PR #23](https://github.com/scottlz0310/mcp-gateway/pull/23))
  - Example: `ROUTE_PUBLIC=/public|http://public-svc:8083|auth=none`
- Persistent token store via `MCP_GATEWAY_TOKEN_STORE_PATH` ([#24](https://github.com/scottlz0310/mcp-gateway/issues/24), [PR #25](https://github.com/scottlz0310/mcp-gateway/pull/25))
  - File-backed store with SHA-256-hashed keys (raw tokens never written to disk)
  - Survives gateway restarts; entries expire after `TOKEN_EXPIRES_IN_SEC` (default 90 days)
  - Falls back to in-memory store when path is not set
- Refresh token grant: `POST /token` now supports `grant_type=refresh_token` with single-use rotation ([#26](https://github.com/scottlz0310/mcp-gateway/issues/26), [PR #27](https://github.com/scottlz0310/mcp-gateway/pull/27))
- Multi-upstream example: `examples/copilot-review-routing/` — single mcp-gateway routing both `github-mcp-server` and `copilot-review-mcp` via `ROUTE_GITHUB` / `ROUTE_COPILOT_REVIEW` ([#19](https://github.com/scottlz0310/mcp-gateway/issues/19))
  - `copilot-review-mcp` requires no code changes; its Go `ServeMux` `/mcp/` subtree handler matches the forwarded path correctly
  - Includes `docker-compose.yml`, `.env.example`, and a dedicated `README.md`

### Changed

- Abstracted `internal/auth` behind a `Provider` interface. GitHub OAuth HTTP logic extracted to `internal/auth/provider/github.go`. External interface (env vars, endpoints, OAuth flow) is unchanged ([#2](https://github.com/scottlz0310/mcp-gateway/issues/2)).
- Reverse proxy now injects `X-Authenticated-User` header into upstream requests. `X-GitHub-Login` continues to be sent for backward compatibility ([#2](https://github.com/scottlz0310/mcp-gateway/issues/2)).

### Fixed

- Docker image now pre-creates `/data` directory so `MCP_GATEWAY_TOKEN_STORE_PATH=/data/tokens.json` works without a manually created volume directory ([#28](https://github.com/scottlz0310/mcp-gateway/issues/28), [PR #29](https://github.com/scottlz0310/mcp-gateway/pull/29))
- `.gitignore`: added `*.exe` to exclude Windows build artifacts

### Internal

- Removed GitHub-specific HTTP calls from `auth.Handler`; delegated to `provider.Provider`.
- Renamed middleware context key `github_login` → `authenticated_user` (internal only; external compatibility maintained).

[Unreleased]: https://github.com/scottlz0310/mcp-gateway/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/scottlz0310/mcp-gateway/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/scottlz0310/mcp-gateway/releases/tag/v0.1.0
