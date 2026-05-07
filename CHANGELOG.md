# Changelog

All notable changes to this project will be documented in this file.

This format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and versioning follows [Semantic Versioning](https://semver.org/).

## [Unreleased]

### CI / Infrastructure

- CI pipeline hardening ([#43](https://github.com/scottlz0310/mcp-gateway/issues/43))
  - Added `govulncheck` job that scans dependencies for known Go vulnerabilities. The job fails when vulnerabilities are detected, and the `build` job lists `govulncheck` in its `needs:` so Docker image build/publish is blocked when the scan fails. `govulncheck` itself is pinned to `v1.1.4` for reproducibility.
  - Added `.golangci.yml` with explicit linter set: `errcheck`, `govet`, `staticcheck`, `unused`, `revive` (instead of relying on `golangci-lint` defaults)
  - Pinned `golangci-lint` to `v2.12.2` and `golangci/golangci-lint-action` to `v9` (was `version: latest`) for CI reproducibility
  - Raised codecov patch coverage target from 70% to 75%
  - revive ruleset disables `package-comments`, `exported`, and `unused-parameter` to align with the project comment policy (comments only when the *why* is non-obvious)

### Added

- RFC 8707 `resource` parameter support across all token acquisition flows ([#57](https://github.com/scottlz0310/mcp-gateway/issues/57), #49 PR-C)
  - `/authorize`, `/device_authorization`, and `grant_type=refresh_token` all accept an optional `resource` parameter to bind the issued token to a specific audience
  - Discovery metadata now advertises `resource_parameter_supported: true`
  - The requested `resource` on `grant_type=refresh_token` must equal or be a sub-path of the audience originally recorded on the refresh token; broadening or cross-route changes are rejected with `invalid_target`
  - Legacy refresh tokens issued before audience tracking (empty stored audience) accept any registered resource during the grace period
  - The consumed refresh token is restored on validation failure so clients can retry with a corrected `resource` value

### Migration

- **`token_audience_strict`**: Enabling `MCP_GATEWAY_TOKEN_AUDIENCE_STRICT=true` (or `token_audience_strict: true`) is only safe when **all** of the following conditions are met:
  1. **Persistent token store required** — Set `MCP_GATEWAY_TOKEN_STORE_PATH` / `token_store_path`. With an in-memory store, audience metadata is lost on cache eviction, making those tokens unusable. The gateway now logs a startup warning if strict mode is combined with an in-memory store.
  2. **All active tokens carry audience metadata** — Tokens issued before this release have no audience recorded. A refresh *without* a `resource` parameter rotates the token but keeps it as a legacy (no-audience) token indefinitely. The 90-day TTL window is **not** automatically sufficient — it only holds if all active clients have refreshed with `resource` or re-authenticated at least once since this release.
  3. **Recommended approach** — Monitor the `"token without audience accepted during grace period"` log entries. Once they disappear across your longest-lived sessions, it is safe to enable strict mode.

### Roadmap

- Multi-audience tokens (a single opaque token carrying multiple `aud` values, e.g., `["https://gw.example/mcp/a", "https://gw.example/mcp/b"]`) are recorded as a future candidate and are not part of the current release.

## [0.3.0] - 2026-05-20

- `MCP_GATEWAY_PUBLIC_URL` / `gateway.public_url` — canonical URL used for OAuth callbacks, discovery metadata, and PRM ([#48](https://github.com/scottlz0310/mcp-gateway/issues/48))
- `MCP_GATEWAY_BIND_ADDR` / `gateway.bind_addr` — HTTP listener bind address, separate from the public URL ([#48](https://github.com/scottlz0310/mcp-gateway/issues/48))
- `docs/operations.md` — migration guide: `bind_addr` vs `public_url`, GitHub OAuth App callback URL update, Docker and bare-binary deployment notes
- Per-route Protected Resource Metadata documents (MCP Authorization Spec 2025-06-18, RFC 9728 §3.1) — partial delivery of [#49](https://github.com/scottlz0310/mcp-gateway/issues/49) (PR-A of 3)
  - Each authenticated route with a non-root prefix now exposes `GET /.well-known/oauth-protected-resource{prefix}` whose `resource` field is the route's canonical absolute URL (e.g. `<public_url>/mcp/copilot-review`)
  - `WWW-Authenticate.resource_metadata` on 401 responses points clients at the route-scoped PRM URL instead of the gateway-wide one
  - Root-prefix routes (`/`) intentionally skip per-route PRM registration and continue to use the gateway-wide `/.well-known/oauth-protected-resource`, since `resource == public_url` is identical and a per-route trailing-slash pattern would shadow other PRM URLs in `http.ServeMux`
  - The gateway-wide `GET /.well-known/oauth-protected-resource` is preserved for backward compatibility
  - `auth.Handler.RouteProtectedResourceMetadata(resource string) http.HandlerFunc` and `middleware.WithResourceMetadataURL(url string)` added
- Trusted reverse proxy header support — partial delivery of [#49](https://github.com/scottlz0310/mcp-gateway/issues/49) (PR-B of 3, [#56](https://github.com/scottlz0310/mcp-gateway/issues/56))
  - `MCP_GATEWAY_TRUSTED_PROXIES` / `gateway.trusted_proxies` accepts a CIDR allowlist for immediate reverse proxy peers
  - `internal/middleware.ProxyHeaders` applies `X-Forwarded-Proto`, `X-Forwarded-Host`, and `X-Forwarded-For` only for trusted peers, and strips forwarded headers from untrusted requests
  - Access logs and setup-mode HTTPS checks now see the trusted forwarded client IP / scheme when the middleware is enabled
  - Invalid trusted proxy CIDRs fail startup instead of being ignored
  - **Note**: #49 spans three PRs and is intentionally not closed by PR-A or PR-B alone. PR-C ([#57](https://github.com/scottlz0310/mcp-gateway/issues/57), token `aud` claim and grace period) follows in a subsequent release. #49 will be closed once all three PRs are merged.

### Changed

- Default bind address changed from all interfaces (`:<port>`) to loopback-only (`127.0.0.1:8080`); Docker users must set `MCP_GATEWAY_BIND_ADDR=0.0.0.0:8080`
- Default public URL changed from `http://localhost:8080` to `http://127.0.0.1:8080`

### Deprecated

- `MCP_GATEWAY_BASE_URL` / `gateway.base_url` — replaced by `MCP_GATEWAY_PUBLIC_URL` / `gateway.public_url`. A startup warning is emitted when the deprecated setting is detected. The alias will be removed in a future release.

### Migration notes

Docker Compose users **must** add `MCP_GATEWAY_BIND_ADDR: 0.0.0.0:<port>` (replacing
`<port>` with the port your gateway uses, typically `8080`) so the container
binds on all interfaces and Docker port-forwarding continues to work. See
[`docs/operations.md`](docs/operations.md) for the full cutover procedure.

**Per-route PRM (#49 PR-A) — upgrade hints for MCP clients**

- MCP clients that already cache `/.well-known/oauth-protected-resource` continue to work unchanged: the gateway-wide PRM is preserved and its `resource` field is unchanged (= `public_url`).
- Strict spec-2025-06-18 clients that fetch per-route PRM (`/.well-known/oauth-protected-resource{prefix}`) now receive a route-scoped `resource` value (`<public_url>{prefix}`) and should re-acquire tokens scoped to that resource if they previously cached gateway-wide tokens.
- 401 responses on authenticated, non-root routes now advertise the route-scoped PRM in `WWW-Authenticate.resource_metadata`. Clients that follow this header to discover the AS endpoint will end up with route-scoped tokens automatically; no client-side configuration change is required.
- No token invalidation is performed by this release. Audience checking will land in PR-C ([#57](https://github.com/scottlz0310/mcp-gateway/issues/57)) with a grace period for previously-issued tokens; review that PR's release notes when it ships.

**Reverse proxy deployments (#49 PR-B)**

- If TLS terminates before mcp-gateway, keep `MCP_GATEWAY_PUBLIC_URL` / `gateway.public_url` set to the external origin clients use.
- Add `MCP_GATEWAY_TRUSTED_PROXIES` or `gateway.trusted_proxies` with valid CIDR values for the immediate proxy peers (for example `127.0.0.1/32,10.0.0.0/8`).
- Direct client-supplied `X-Forwarded-*` headers are ignored unless the immediate peer is trusted.

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

[Unreleased]: https://github.com/scottlz0310/mcp-gateway/compare/v0.3.0...HEAD
[0.3.0]: https://github.com/scottlz0310/mcp-gateway/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/scottlz0310/mcp-gateway/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/scottlz0310/mcp-gateway/releases/tag/v0.1.0
