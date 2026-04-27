# Changelog

All notable changes to this project will be documented in this file.

This format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and versioning follows [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Changed

- Abstracted `internal/auth` behind a `Provider` interface. GitHub OAuth HTTP logic extracted to `internal/auth/provider/github.go`. External interface (env vars, endpoints, OAuth flow) is unchanged ([#2](https://github.com/scottlz0310/mcp-gateway/issues/2)).
- Reverse proxy now injects `X-Authenticated-User` header into upstream requests. `X-GitHub-Login` continues to be sent for backward compatibility ([#2](https://github.com/scottlz0310/mcp-gateway/issues/2)).

### Internal

- Removed GitHub-specific HTTP calls from `auth.Handler`; delegated to `provider.Provider`.
- Renamed middleware context key `github_login` → `authenticated_user` (internal only; external compatibility maintained).
