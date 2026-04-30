# Changelog

All notable changes to this project will be documented in this file.

This format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and versioning follows [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

- Device Flow per-device polling serialization ([#16](https://github.com/scottlz0310/mcp-gateway/issues/16))
  - `AcquireDevicePolling` / `ReleaseDevicePolling` added to `internal/auth.Store` to serialize concurrent GitHub polling per `device_code`
  - Concurrent requests presenting the same `device_code` while one is already polling GitHub receive `authorization_pending` immediately, preventing `slow_down` / rate-limit responses from GitHub (RFC 8628 §3.5)

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

[Unreleased]: https://github.com/scottlz0310/mcp-gateway/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/scottlz0310/mcp-gateway/releases/tag/v0.1.0
