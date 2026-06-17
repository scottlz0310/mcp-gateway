# Changelog

All notable changes to this project will be documented in this file.

This format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and versioning follows [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

- Switch provider from GitHub OAuth Apps to GitHub Apps (user-to-server OAuth) ([#139](https://github.com/scottlz0310/mcp-gateway/issues/139))
  - `ghu_` user access tokens (GitHub Apps) accepted alongside classic `gho_` tokens — no code changes required, no prefix validation present
  - README and README.ja.md: Step 1 updated to "Create A GitHub App" with both `/callback` and `/device_callback` callback URL registration instructions, minimum permissions (`Email addresses: Read-only`), and migration note from OAuth Apps
  - docs/configuration.md: "GitHub OAuth App" references updated to "GitHub App" throughout
  - Internal: test fixture updated to `ghu_` prefix; factory error message updated to "GitHub App credentials"
- Device Authorization Grant (RFC 8628) fully implemented as gateway-native flow ([#130](https://github.com/scottlz0310/mcp-gateway/issues/130))
  - `POST /device_authorization` now generates a gateway-own `device_code` and `user_code` (XXXX-XXXX format); no longer delegates to GitHub's device flow
  - `GET /activate` renders a user_code entry form; `POST /activate` validates the code and redirects to the standard `/authorize` flow
  - `GET /device_callback` receives the provider callback, exchanges the code, and marks the device session as approved
  - Client polling (`POST /token?grant_type=device_code`) retrieves the approved token atomically (double-issuance prevented via `ConsumeApprovedDevice`)
  - `slow_down` enforced via `CheckAndAdvancePollInterval`; interval increased by 5 s on each slow-down (`IncreaseDeviceInterval`)
  - `verification_uri_complete` pre-fills the user_code in the `/activate` form
  - BaseURL hostname automatically added to `AllowedRedirectHosts` so `/device_callback` can be used as `redirect_uri`
  - `builtin` mode issues gateway-signed JWT; `github` mode returns GitHub opaque token (consistent with `/authorize` flow)
  - Removed GitHub-delegated device flow: `startGitHubDeviceFlow`, `pollGitHubDeviceToken`, `githubDeviceHTTPError`, `githubRateLimited`, `githubClient`
- Separate `aud` claim by route via `required_audience` config ([#129](https://github.com/scottlz0310/mcp-gateway/issues/129))
  - `RouteConfig.required_audience` / `Route.RequiredAudience` field: per-route JWT audience (e.g. `"mcp-server"`, `"external-mcp"`); defaults to `"mcp-gateway"`
  - `/token` and device-authorize endpoints accept `resource=<route-name>` (RFC 8707); gateway resolves audience from route config and stamps it in issued access tokens
  - `"mcp-gateway"` narrowing: refresh token with gateway-wide `mcp-gateway` audience may be narrowed to any per-route audience on subsequent refresh
  - `ResourceAudienceMap` (`auth.Config`) replaces the former `AllowedAudiences` slice; keys are route names, values are `required_audience` values
  - `routeResource` (RFC 9728 PRM discovery URL) is kept as a separate URL-form identifier and is not used for JWT aud validation
- Migrate refresh token store from file-backed JSON to SQLite ([#134](https://github.com/scottlz0310/mcp-gateway/issues/134))
  - Atomic `Revoke` / `RevokeFamily` via single-statement `UPDATE` — eliminates in-process TOCTOU between `Lookup` and `Revoke`
  - Flush-failure rollback is now guaranteed by SQLite transactions (no manual `prev`-state bookkeeping)
  - `Sweep` removes expired entries via indexed `DELETE` (no full-scan)
  - Store file renamed from `tokens.json.refresh` (JSON) to `tokens.json.refresh.db` (SQLite WAL)
  - Automatic one-time migration: existing `tokens.json.refresh` is imported on first startup and renamed to `tokens.json.refresh.migrated`
  - `Handler.Close()` / `Store.Close()` added to release the database connection
- Add refresh token rotation and reuse detection (RFC 6819 §5.2.2.3) ([#128](https://github.com/scottlz0310/mcp-gateway/issues/128))
  - Token family tracking: every refresh token is associated with a `family_id` generated at authorization-code issuance and inherited across rotations
  - Reuse detection: presenting a revoked (already-used) refresh token immediately revokes the entire token lineage (`invalid_grant`)
  - Soft-revoke on rotation: consumed tokens are marked `revoked=true` and retained until expiry so replay attacks can be detected within the expiry window
  - `RevokeFamily` / `Revoke` / `LookupAny` methods added to `RefreshTokenStore`
  - File-backed store persists `family_id` and `revoked` flag across gateway restarts (`tokens.json.refresh`)
  - Both `builtin` and `github` modes apply family tracking
- Add `OAUTH_PROVIDER=builtin` mode: GitHub OAuth 2.0 PKCE social login with gateway-issued RS256 JWT ([#127](https://github.com/scottlz0310/mcp-gateway/issues/127))
  - gateway が自身の RS256 JWT（access_token + id_token + refresh_token）を発行する
  - GitHub は identity 取得のみに使用し、GitHub access_token はクライアントに渡さず callback 後に破棄する
  - `/token`（authorization_code grant）でゲートウェイ署名付き JWT を発行
  - `/token`（refresh_token grant）でゲートウェイ JWT を再発行（GitHub API 不要）
  - `ValidateToken` でゲートウェイ JWT をローカルで RS256 検証（GitHub API 呼び出し不要）
  - 既存の `OAUTH_PROVIDER=github` モードとの並存を維持
- Add persistent OAuth audit diagnostics ([#102](https://github.com/scottlz0310/mcp-gateway/issues/102))
  - Record authorize, callback, token exchange, identity resolution, refresh, and provider rotation outcomes as structured events
  - Persist redacted JSON Lines outside Git worktrees with OS-specific user-state defaults and size/age/count rotation
  - Add `GET /internal/v1/auth/failures` on the existing loopback and shared-secret internal API boundary
- Add OIDC provider support ([#98](https://github.com/scottlz0310/mcp-gateway/pull/98))
  - Support mcp-gateway as an OIDC Identity Provider to support agy CLI
  - Support OIDC RSA private key persistence
- Add RFC 8252 custom URL scheme redirect_uri support ([#121](https://github.com/scottlz0310/mcp-gateway/issues/121))
  - Allow native app clients (e.g. agy CLI) to use custom URL scheme redirect_uris such as `antigravity://oauth-callback`
  - Default permitted schemes: `antigravity`, `antigravity-insiders`
  - Configurable via `MCP_GATEWAY_ALLOWED_REDIRECT_SCHEMES` env var or `gateway.allowed_redirect_schemes` in `config.yaml`

### Fixed

- Preserve an upstream base path without adding a trailing slash for exact-prefix requests ([#111](https://github.com/scottlz0310/mcp-gateway/issues/111))
- Strip routing prefix before forwarding to upstream ([#108](https://github.com/scottlz0310/mcp-gateway/issues/108))
  - Routing prefix (e.g. `/mcp/github`) is now stripped from the request path before proxying to prevent `405 Method Not Allowed` errors on path-strict MCP servers such as `github-mcp-server` and `playwright-mcp`
  - Prefix is stripped before `SetURL` so that upstream base paths (e.g. `https://mcp.cloudflare.com/mcp`) are correctly joined with the stripped path
- Fix proxy authentication failure for github-mcp-server ([#104](https://github.com/scottlz0310/mcp-gateway/pull/104))
  - Pass `GITHUB_PERSONAL_ACCESS_TOKEN` to mcp-gateway environment in docker-compose.yml
  - Configure `/mcp/github` route with `upstream_bearer_token_env=GITHUB_PERSONAL_ACCESS_TOKEN` to prevent client token expiration from leaking to the github-mcp-server upstream
- Fix redirect_uri host verification configuration ([#100](https://github.com/scottlz0310/mcp-gateway/issues/100))
  - Add `MCP_GATEWAY_ALLOWED_REDIRECT_HOSTS` environment variable (comma-separated) and `gateway.allowed_redirect_hosts` (config.yaml) configuration path to allow registering external redirect hostnames
  - Add `antigravity.google` to the default allowed redirect hosts list

### Documentation

- `docs/architecture.md`: define mcp-gateway's role as MCP reverse proxy / routing gateway / auth boundary within the review platform; document responsibility boundaries with thread-owl, mcp-resource-subscriber, review-raven, and Mcp-Docker ([#92](https://github.com/scottlz0310/mcp-gateway/issues/92))
- `README.md`: expand Repository Stack table to the full five-repo review infrastructure ([#92](https://github.com/scottlz0310/mcp-gateway/issues/92))
- `docs/spike-105-auth-issue-investigation.md`: add spike investigation report on 401 authentication errors across routed MCP servers ([#105](https://github.com/scottlz0310/mcp-gateway/issues/105))

## [0.5.2] - 2026-06-10

### Fixed

- `ci.yml`: main push で `:latest` が更新されないよう `type=raw,value=latest,enable={{is_default_branch}}` を削除（`:main` + `:sha-*` のみ発行）([#93](https://github.com/scottlz0310/mcp-gateway/issues/93))
- `release.yml`: prerelease タグでも `:latest` が付く問題を修正。`type=raw,value=latest` を削除し `latest=auto`（デフォルト）に委ねることで非 prerelease semver タグにのみ `:latest` を付与 ([#93](https://github.com/scottlz0310/mcp-gateway/issues/93))

### Documentation

- `CONTRIBUTING.md` を新規作成し、prerelease タグは semver pre-release 形式（`-` 含む）必須である旨を明記 ([#94](https://github.com/scottlz0310/mcp-gateway/pull/94))

## [0.5.1] - 2026-06-01

### Fixed

- `parseRoutes` now silently skips `ROUTE_*` environment variables whose value is
  empty or whitespace-only ([#86](https://github.com/scottlz0310/mcp-gateway/pull/86)).
  This enables docker-compose conditional patterns such as
  `ROUTE_FOO=${TOKEN:+/prefix|upstream|opts}` — when `TOKEN` is absent the expansion
  yields an empty string, and the route is simply not registered instead of causing a
  startup error. Pairs with Mcp-Docker v2.12.0.

### Security

- Updated `golang.org/x/crypto` to v0.52.0 ([#85](https://github.com/scottlz0310/mcp-gateway/pull/85)).

## [0.5.0] - 2026-05-18

### Added

- `upstream_bearer_token_env` option for `ROUTE_*` environment variables
  ([#82](https://github.com/scottlz0310/mcp-gateway/pull/82)).
  Allows the gateway to inject a fixed API token from an environment variable as the
  `Authorization: Bearer` header sent to upstream MCP servers.
  - When set, the upstream receives the env-var token instead of the client OAuth token.
  - Fail-closed: gateway refuses to start if the named env var is unset or empty at startup.
  - 401 isolation: upstream 401 on `upstream_bearer_token_env` routes does not invalidate
    the client OAuth cache.
  - Secret protection: the Bearer token value is never written to logs.
  - Per-request re-read: `os.Getenv` is called per request, enabling secret rotation
    without a container restart.

## [0.4.0] - 2026-05-18

### Added

- Generic OAuth environment variables to decouple configuration from GitHub-specific naming ([#5](https://github.com/scottlz0310/mcp-gateway/issues/5)).
  - New canonical variables: `OAUTH_PROVIDER` (default `github`), `OAUTH_CLIENT_ID`, `OAUTH_CLIENT_SECRET`, `OAUTH_SCOPES`.
  - `OAUTH_PROVIDER` is plumbed through to the provider factory and enables future non-GitHub providers (#6).
  - Migration map:

    | New | Legacy (deprecated) |
    |---|---|
    | `OAUTH_PROVIDER` | _(new; default `github`)_ |
    | `OAUTH_CLIENT_ID` | `GITHUB_MCP_CLIENT_ID` |
    | `OAUTH_CLIENT_SECRET` | `GITHUB_MCP_CLIENT_SECRET` |
    | `OAUTH_SCOPES` | `GITHUB_MCP_OAUTH_SCOPES` |
- Transparent rotation of expiring GitHub OAuth user access tokens ([#70](https://github.com/scottlz0310/mcp-gateway/issues/70), Phase A).
  - New `MCP_GATEWAY_GITHUB_REFRESH_ENABLED` / `gateway.github_refresh_enabled` flag enables the rotation path. Defaults to `false`.
  - When the upstream provider advertises `refresh_token` + `expires_in`, the gateway re-uses the refresh token to rotate the access token within ~5 minutes of expiry. The rotated token is forwarded transparently to upstream MCP servers.
  - Rotation is a best-effort optimization: provider failures log `rotation_failed` and fall back to the existing 401-and-reauthenticate path.
  - Provider interface (`internal/auth/provider`) now exposes a normalized `TokenResponse` from `ExchangeCode` and a `RefreshToken` method.
- Delegated background access PoC ([#72](https://github.com/scottlz0310/mcp-gateway/issues/72), Phase B).
  - Optional loopback-only internal API at `POST /internal/v1/whoami` that returns the latest valid GitHub access token for a given subject, rotating transparently when the cached token is near expiry.
  - Enabled only when both `MCP_GATEWAY_INTERNAL_SECRET` (≥32 chars) and `MCP_GATEWAY_INTERNAL_PORT` are set; otherwise the API is not served and a log entry announces the disabled state (fail-closed). Transparent rotation inside the API additionally requires `MCP_GATEWAY_GITHUB_REFRESH_ENABLED=true` (Phase A); without it the API still returns the cached token but never refreshes it.
  - Listener binds to `127.0.0.1` exclusively. Requests authenticate via a shared `Bearer` secret compared in constant time. Body is capped at 4KB and unknown JSON fields are rejected.
  - Response contains `{access_token, token_type, expires_at, scopes}` (no refresh token). Errors use `404 subject_not_found`, `401 invalid_authorization`, `403 loopback_required`, `400 invalid_body`/`missing_subject`, `405 method_not_allowed` (with `Allow: POST`), `502 upstream_failure`, `502 rotation_failed` (returned when the cached token is inside the GitHub refresh leeway window but rotation did not produce a fresh token).
  - Intended consumer: long-lived background workers in upstream MCP servers (e.g. `copilot-review-mcp` watch goroutines) that need a fresh access token outside the normal MCP request path. See `docs/spike-72-delegated-background-access.md` for the design and security model.

### Changed

- OAuth environment variables read precedence: `OAUTH_*` wins over legacy `GITHUB_MCP_*`. If only the legacy variable is set the gateway uses it but logs a one-time deprecation warning per process. If both are set the canonical wins and the legacy value is ignored with a warning. The legacy names will be removed in a future major release. YAML config keys (`auth.github_client_id`, `auth.github_client_secret`, `gateway.oauth_scopes`) are unchanged ([#5](https://github.com/scottlz0310/mcp-gateway/issues/5)).
- `auth.Handler.ValidateToken` now returns a rotated access token alongside the subject so middleware can substitute it in the request context. Internal API only; no public surface affected.

## [0.3.0] - 2026-05-07

### Added

- HTTP request logging middleware and `slog` field normalization ([#42](https://github.com/scottlz0310/mcp-gateway/issues/42), [PR #47](https://github.com/scottlz0310/mcp-gateway/pull/47))
  - Emits one structured `"http request"` log per request with `method`, `path`, `status`, `latency_ms`, and `remote_addr`.
  - Keeps auth, proxy, setup, and startup events on structured `log/slog` output.
- `MCP_GATEWAY_PUBLIC_URL` / `gateway.public_url` and `MCP_GATEWAY_BIND_ADDR` / `gateway.bind_addr` ([#48](https://github.com/scottlz0310/mcp-gateway/issues/48), [PR #51](https://github.com/scottlz0310/mcp-gateway/pull/51))
  - Separates the canonical OAuth/discovery/PRM URL from the HTTP listener address.
- Per-route Protected Resource Metadata documents (MCP Authorization Spec 2025-06-18, RFC 9728 §3.1) ([#49](https://github.com/scottlz0310/mcp-gateway/issues/49), [PR #58](https://github.com/scottlz0310/mcp-gateway/pull/58))
  - Authenticated non-root routes expose `GET /.well-known/oauth-protected-resource/<prefix>` with a route-scoped `resource`.
  - `WWW-Authenticate.resource_metadata` on 401 responses points clients at route-scoped PRM when available.
  - Root-prefix routes continue to use gateway-wide PRM for backward compatibility.
- Trusted reverse proxy header support ([#56](https://github.com/scottlz0310/mcp-gateway/issues/56), [PR #59](https://github.com/scottlz0310/mcp-gateway/pull/59))
  - `MCP_GATEWAY_TRUSTED_PROXIES` / `gateway.trusted_proxies` accepts a CIDR allowlist for immediate reverse proxy peers.
  - Trusted peers may supply `X-Forwarded-Proto`, `X-Forwarded-Host`, and `X-Forwarded-For`; untrusted forwarded headers are stripped.
  - Invalid trusted proxy CIDRs fail startup instead of being ignored.
- RFC 8707 `resource` parameter support and token audience tracking across token acquisition flows ([#57](https://github.com/scottlz0310/mcp-gateway/issues/57), [PR #60](https://github.com/scottlz0310/mcp-gateway/pull/60))
  - `/authorize`, `/device_authorization`, and `grant_type=refresh_token` accept `resource`.
  - Discovery metadata advertises `resource_parameter_supported: true`.
  - `grant_type=refresh_token` may keep the original audience or narrow it to a sub-path; broadening and cross-route changes are rejected with `invalid_target`.

### Changed

- Default bind address changed from all interfaces (`:<port>`) to loopback-only (`127.0.0.1:8080`); Docker deployments should set `MCP_GATEWAY_BIND_ADDR=0.0.0.0:8080`.
- Default public URL changed from `http://localhost:8080` to `http://127.0.0.1:8080`.
- Example Compose configuration was updated for the `bind_addr` / `public_url` split ([PR #52](https://github.com/scottlz0310/mcp-gateway/pull/52)).
- CI pipeline hardening ([#43](https://github.com/scottlz0310/mcp-gateway/issues/43), [PR #62](https://github.com/scottlz0310/mcp-gateway/pull/62))
  - Added `govulncheck` and made the Docker build depend on it.
  - Added explicit `.golangci.yml` linter configuration.
  - Pinned golangci-lint tooling and raised the Codecov patch target to 75%.
- Dependency and GitHub Actions maintenance ([PR #66](https://github.com/scottlz0310/mcp-gateway/pull/66), [PR #67](https://github.com/scottlz0310/mcp-gateway/pull/67)).

### Fixed

- Audience validation accepts ancestor-scoped tokens for route-scoped resources ([#61](https://github.com/scottlz0310/mcp-gateway/issues/61), [PR #63](https://github.com/scottlz0310/mcp-gateway/pull/63))
  - Fixes `token audience mismatch` 401 errors for clients that acquire a gateway-wide token at `public_url` and then initialize multiple authenticated sub-routes.
  - Sibling routes, narrower-recorded-vs-broader-requested, and same-prefix-different-segment cases continue to be rejected.

### Documentation

- Documentation restructuring for operations and configuration ([#44](https://github.com/scottlz0310/mcp-gateway/issues/44), [PR #64](https://github.com/scottlz0310/mcp-gateway/pull/64))
  - Reworked the root README around a front-loaded Getting Started flow.
  - Added `docs/configuration.md` as the environment variable, `config.yaml`, route, token persistence, reverse proxy, and endpoint reference.
  - Expanded `docs/operations.md` with start/stop procedures, health checks, structured log field reference, troubleshooting, and migration notes.
  - Added `docs/README.md` as an index for guides, runbooks, examples, and spike notes.

### Deprecated

- `MCP_GATEWAY_BASE_URL` / `gateway.base_url` — replaced by `MCP_GATEWAY_PUBLIC_URL` / `gateway.public_url`. A startup warning is emitted when the deprecated setting is detected. The alias will be removed in a future release.

### Migration Notes

- Docker Compose users should add `MCP_GATEWAY_BIND_ADDR=0.0.0.0:<port>` so container port forwarding continues to work. Keep `MCP_GATEWAY_PUBLIC_URL` set to the URL visible to the browser and OAuth clients.
- If TLS terminates before mcp-gateway, keep `MCP_GATEWAY_PUBLIC_URL` / `gateway.public_url` set to the external origin and configure `MCP_GATEWAY_TRUSTED_PROXIES` / `gateway.trusted_proxies` for the immediate proxy peers.
- Enabling `MCP_GATEWAY_TOKEN_AUDIENCE_STRICT=true` (or `token_audience_strict: true`) is safe only after all active tokens carry audience metadata. Monitor `"token without audience accepted during grace period"` logs before enabling strict mode.

### Roadmap

- Multi-audience tokens (a single opaque token carrying multiple `aud` values, e.g. `["https://gw.example/mcp/a", "https://gw.example/mcp/b"]`) are recorded as a future candidate and are not part of this release.

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

[Unreleased]: https://github.com/scottlz0310/mcp-gateway/compare/v0.5.2...HEAD
[0.5.2]: https://github.com/scottlz0310/mcp-gateway/compare/v0.5.1...v0.5.2
[0.5.1]: https://github.com/scottlz0310/mcp-gateway/compare/v0.5.0...v0.5.1
[0.5.0]: https://github.com/scottlz0310/mcp-gateway/compare/v0.4.0...v0.5.0
[0.4.0]: https://github.com/scottlz0310/mcp-gateway/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/scottlz0310/mcp-gateway/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/scottlz0310/mcp-gateway/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/scottlz0310/mcp-gateway/releases/tag/v0.1.0
