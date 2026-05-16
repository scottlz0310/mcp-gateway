# Auth Error Contract

> **Phase C — Structured Error Contract** (Issue #73)
>
> This document is the authoritative reference for the error code contract between mcp-gateway
> and its consumers: MCP clients (public API), upstream MCP servers (internal API), and
> operator tooling. It covers trigger conditions, wire representation, and the mapping to
> copilot-review-mcp's internal error taxonomy.

---

## 1. Public Client Contract

MCP clients authenticate against gateway-protected routes via RFC 6750 Bearer tokens. All
error responses carry a JSON body `{"error": "<code>", "error_description": "..."}` and the
headers below.

### 1.1 Error Codes

| Error code | HTTP status | `WWW-Authenticate error=` | Trigger | Recommended client action |
|---|---|---|---|---|
| `invalid_request` | 401 | **omitted** (intentional — see §1.2) | No `Authorization` header, or header is not in `Bearer <token>` form | Start the gateway OAuth flow (follow the `resource_metadata` URL in the `WWW-Authenticate` header) |
| `invalid_token` | 401 | `error="invalid_token"` | Token is expired, cryptographically invalid, or addressed to the wrong audience | Re-authenticate via the gateway OAuth flow |
| `upstream_error` | 503 | *(no `WWW-Authenticate` header)* | The upstream OAuth provider (GitHub) returned 5xx or was unreachable during token validation | Retry with exponential backoff; no credential change required |

### 1.2 `error=` Omission for `invalid_request` — Security Design

RFC 6750 §3.1 permits omitting `error=` when the request lacked credentials entirely. The
gateway applies the same omission when the `Authorization` header is malformed (not in
`Bearer <token>` form) — `extractBearer()` returns `""` in both cases, and both result in
`invalid_request`:

```
# invalid_request — no error= attribute
WWW-Authenticate: Bearer realm="mcp-gateway", resource_metadata="<url>"

# invalid_token — error= is present
WWW-Authenticate: Bearer realm="mcp-gateway", error="invalid_token", error_description="...", resource_metadata="<url>"
```

**Rationale:** Omitting `error="invalid_request"` avoids revealing whether the request was malformed
versus simply unauthenticated. The response still advertises the Bearer challenge and the
`resource_metadata` URL needed by legitimate MCP clients — the Bearer scheme itself is not hidden.

Implementation reference: `internal/middleware/auth.go:writeUnauthorized()` — the condition
`if errCode == "invalid_token"` gates the `error=` attribute.

### 1.3 Backward Compatibility Guarantee

The three codes above (`invalid_request`, `invalid_token`, `upstream_error`) are covered by tests
in `internal/middleware/auth_test.go` (`TestAuthMissingToken`, `TestAuthInvalidToken`,
`TestAuthUpstreamError`). Any change to their wire shape requires updating those tests and
incrementing the semver minor version.

---

## 2. Internal Delegated Access Contract

Upstream MCP servers (e.g. copilot-review-mcp) obtain a fresh gateway-managed access token by
calling `POST /internal/v1/whoami` on the internal listener. This endpoint is **loopback-only**
and authenticates via a pre-shared secret.

Error responses carry `{"error": "<code>"}` (no `error_description` field) to reduce the
information surface on this trust boundary.

### 2.1 Error Codes

| Error code | HTTP status | Trigger | Caller action |
|---|---|---|---|
| `method_not_allowed` | 405 | Non-`POST` method | Fix the HTTP method; this is a caller bug |
| `loopback_required` | 403 | Request originated from a non-loopback address | Ensure the caller connects to the internal API on loopback — the listener always binds to `127.0.0.1:${MCP_GATEWAY_INTERNAL_PORT}` |
| `invalid_authorization` | 401 | `Authorization: Bearer` secret missing or does not match `MCP_GATEWAY_INTERNAL_SECRET` | Fix the shared secret configuration |
| `invalid_body` | 400 | Malformed JSON, body exceeds 4 KiB, unknown fields, or trailing bytes after the JSON object | Fix the request body |
| `missing_subject` | 400 | `subject` field is omitted or empty (including whitespace-only) | Supply a non-empty subject |
| `subject_not_found` | 404 | No entry in the in-memory subject index for the requested subject — the user has never authenticated on this instance, the session was purged, or the process was recently restarted (the in-memory index starts empty after restart and re-seeds as bearer tokens are validated on protected routes) | Trigger the user to re-authenticate; after a process restart the error may be transient — the index rebuilds as users access protected routes |
| `rotation_failed` | 502 | Token is near expiry, rotation was attempted but did not yield a fresh token (covers both transient provider/network errors and explicit rejection by GitHub's token endpoint) | Retry after a brief delay; if the error persists, trigger the user to re-authenticate — the refresh token may have been revoked |
| `upstream_failure` | 502 | Any other resolver error, or the resolver returned an empty access token | Retry after a brief delay; if persistent, treat as `subject_not_found` and prompt re-auth |

### 2.2 Naming Note: `upstream_error` vs `upstream_failure`

These are **two distinct codes at two different layers**, not aliases:

| Code | Layer | HTTP status | Meaning |
|---|---|---|---|
| `upstream_error` | Public API (`middleware/auth.go`) | 503 | The *OAuth provider* (GitHub) is unreachable when validating the incoming Bearer token |
| `upstream_failure` | Internal API (`internalapi/handler.go`) | 502 | The *gateway resolver* failed to produce a usable access token for the requested subject |

The asymmetry in naming is deliberate: the two codes appear in separate subsystems, serve
different audiences, and have different retry semantics. They should not be merged.

### 2.3 Conceptual Category: AUTH_CONTEXT_UNAVAILABLE

Issue #72 (Phase B) considered introducing a single error code `auth_context_unavailable` to
cover the condition "the gateway has no usable auth context for this subject." After the Phase B
go/no-go verdict this was **decided against** — no new error code was added to the codebase.

Instead, the two existing codes cover the concept:

| Code | Why the context is unavailable |
|---|---|
| `subject_not_found` | No token has ever been cached for this subject (user never authenticated on this gateway instance, or cache was purged) |
| `rotation_failed` | A token exists but rotation did not yield a fresh token — may be a transient provider/network error or permanent refresh-token rejection |

`subject_not_found` always requires re-authentication. `rotation_failed` should be retried first;
if the error persists, trigger the end-user to re-authenticate via the gateway's public OAuth flow.
Callers **SHOULD** treat persistent `rotation_failed` as "prompt re-authentication," but a single
transient occurrence warrants a retry before escalating.

Implementation reference: `internal/auth/handler.go:EnsureFreshAccessTokenForSubject()` —
returns `auth.ErrSubjectNotFound` and `auth.ErrRotationFailed` as distinct typed errors;
`internalapi/handler.go` maps them to the codes above.

---

## 3. copilot-review-mcp Mapping Contract

This section documents how gateway error codes propagate through copilot-review-mcp's internal
error taxonomy. It is primarily useful for maintainers of both services.

### 3.1 Gateway Internal API → Sentinel Errors

`copilot-review-mcp/internal/github/gateway_token_source.go` maps the HTTP status codes of
`/internal/v1/whoami` responses to Go sentinel errors:

| `/whoami` HTTP status | Gateway error code | Sentinel error |
|---|---|---|
| 200 | *(success)* | — |
| 200 (malformed body) | `expires_at` missing or unparseable | `ErrGatewayInvalidExpiry` |
| 401 | `invalid_authorization` | `ErrGatewayUnauthorized` |
| 403 | `loopback_required` | `ErrGatewayLoopbackRequired` |
| 404 | `subject_not_found` | `ErrGatewaySubjectGone` |
| 502 | `rotation_failed` | `ErrGatewayRotationFailed` |
| 502 | `upstream_failure` (or unrecognised body) | `ErrGatewayUpstreamFailure` |
| other 4xx | `method_not_allowed` / `invalid_body` / `missing_subject` | `ErrGatewayBadRequest` |

`ErrGatewayUnauthorized`, `ErrGatewayLoopbackRequired`, and `ErrGatewayBadRequest` always
indicate configuration errors; they should never occur in a correctly configured deployment.

`ErrGatewayRotationFailed` and `ErrGatewayUpstreamFailure` are distinct sentinels since
copilot-review-mcp PR #34 (Issue #33): `gatewayTokenSource.Token()` now parses the JSON `error`
body of HTTP 502 responses to emit the appropriate sentinel.

### 3.2 Watch Manager: Sentinel Errors → `FailureReason`

`copilot-review-mcp/internal/watch/manager.go` classifies polling failures into three
`FailureReason` values:

| `FailureReason` | Meaning |
|---|---|
| `AUTH_EXPIRED` | The auth context expired; the watch cannot continue until the user re-authenticates |
| `GITHUB_ERROR` | A GitHub API error that is not an auth expiry (may be transient) |
| `INTERNAL_ERROR` | Watch setup or database failure |

The manager uses `ghclient.IsAuthError(err)` and `ghclient.IsGatewayAuthError(err)` to
distinguish `AUTH_EXPIRED` from `GITHUB_ERROR`. `IsAuthError` detects HTTP 401 errors from
the **GitHub API**. `IsGatewayAuthError` recognises the gateway sentinels that require
re-authentication. `ErrGatewayUpstreamFailure` is handled separately by a consecutive-failure
budget: after `N` consecutive failures the watch escalates to `AUTH_EXPIRED`.

**Current (actual) mapping:**

| Sentinel error | `IsGatewayAuthError(err)` | `FailureReason` (current) | Semantically correct? |
|---|---|---|---|
| `ErrGatewaySubjectGone` | `true` | `AUTH_EXPIRED` | ✅ Fixed ([scottlz0310/copilot-review-mcp PR #36](https://github.com/scottlz0310/copilot-review-mcp/pull/36)) |
| `ErrGatewayRotationFailed` | `true` | `AUTH_EXPIRED` | ✅ Fixed ([scottlz0310/copilot-review-mcp PR #36](https://github.com/scottlz0310/copilot-review-mcp/pull/36)) |
| `ErrGatewayUpstreamFailure` (transient, below threshold) | `false` | `GITHUB_ERROR` (continues watch) | ✅ Fixed ([scottlz0310/copilot-review-mcp PR #38](https://github.com/scottlz0310/copilot-review-mcp/pull/38)) |
| `ErrGatewayUpstreamFailure` (persistent, above threshold) | `false` → escalated | `AUTH_EXPIRED` | ✅ Fixed ([scottlz0310/copilot-review-mcp PR #38](https://github.com/scottlz0310/copilot-review-mcp/pull/38)) |
| GitHub API 401 | *(IsAuthError)* `true` | `AUTH_EXPIRED` | ✅ |
| GitHub API 5xx / other | `false` | `GITHUB_ERROR` | ✅ |

### 3.3 Tool Call Path: `AuthErrorType`

When a copilot-review-mcp **tool call** fails (not a background watch), errors are classified by
`ClassifyGitHubError()` into `autherr.AuthErrorType`:

| `AuthErrorType` | Meaning |
|---|---|
| `AUTH_REQUIRED` | No credentials present at all |
| `REAUTH_REQUIRED` | Credentials expired (GitHub 401) |
| `TOKEN_REFRESH_FAILED` | Refresh token was explicitly rejected |
| `PERMISSION_DENIED` | GitHub 403 |
| `RATE_LIMITED` | GitHub rate limit (primary or secondary) |
| `NOT_FOUND` | GitHub 404 |
| `VALIDATION_ERROR` | GitHub 400 / 422 |
| `TRANSIENT_UPSTREAM_ERROR` | GitHub 5xx (retryable) |

`ClassifyGitHubError` is built around both GitHub API HTTP status codes and gateway sentinel
errors. Gateway sentinels are checked first (before generic HTTP-status checks) because they
carry more precise semantics.

**Gateway sentinel → `AuthErrorType` mapping (as of PR #32):**

| Sentinel | `AuthErrorType` | Rationale |
|---|---|---|
| `ErrGatewayRotationFailed` | `TOKEN_REFRESH_FAILED` | Gateway reported `rotation_failed` (may indicate token rejection, transient provider failure, or malformed provider response); re-auth recommended if persistent |
| `ErrGatewaySubjectGone` | `REAUTH_REQUIRED` | Subject removed or revoked; re-auth required |
| `ErrGatewayUpstreamFailure` | `TRANSIENT_UPSTREAM_ERROR` | Transient resolver failure; retry may succeed |
| `ErrGatewayUnauthorized` | `AUTH_REQUIRED` | Shared-secret misconfiguration; no usable token |
| `ErrGatewayLoopbackRequired` | `AUTH_REQUIRED` | Endpoint not on loopback; configuration error |
| `ErrGatewayBadRequest` | `VALIDATION_ERROR` | Request arguments rejected; do not retry |
| `ErrGatewayInvalidExpiry` | `TRANSIENT_UPSTREAM_ERROR` | Malformed whoami response (missing/invalid `expires_at`); retry may succeed |

---

## 4. Known Gaps — All Resolved

All three gaps identified at Phase C document creation have been resolved in
copilot-review-mcp. The sections below are preserved for historical reference and
cross-linked to the relevant PRs.

### Gap 1 — ✅ Resolved (scottlz0310/copilot-review-mcp PR #36)

**`ErrGatewaySubjectGone` was classified as `GITHUB_ERROR` not `AUTH_EXPIRED`**

**Location:** `copilot-review-mcp/internal/watch/manager.go`

When a watch's `gatewayTokenSource.Token()` call returned `ErrGatewaySubjectGone` (HTTP 404
from gateway), `IsAuthError` returned `false` because it only recognised GitHub API 401
patterns. The watch therefore set `FailureReason = GITHUB_ERROR`.

**Resolution:** `ghclient.IsGatewayAuthError` was introduced and wired into the watch manager.
It returns `true` for `ErrGatewaySubjectGone` and `ErrGatewayRotationFailed`, causing the watch
to set `FailureReason = AUTH_EXPIRED` for both.
Fixed by [scottlz0310/copilot-review-mcp#31](https://github.com/scottlz0310/copilot-review-mcp/issues/31),
landed in [scottlz0310/copilot-review-mcp PR #36](https://github.com/scottlz0310/copilot-review-mcp/pull/36).

### Gap 2 — ✅ Resolved (scottlz0310/copilot-review-mcp PR #32)

**Gateway sentinel errors had no `AuthErrorType` mapping**

**Location:** `copilot-review-mcp/internal/github/classify.go`

When a tool call failed due to a gateway sentinel error, `ClassifyGitHubError` did not produce
an `AuthErrorType`.

**Resolution:** Explicit cases for all gateway sentinel errors were added to
`ClassifyGitHubError`. See §3.3 for the current mapping table.
Fixed by [scottlz0310/copilot-review-mcp#32](https://github.com/scottlz0310/copilot-review-mcp/issues/32).

### Gap 3 — ✅ Resolved (scottlz0310/copilot-review-mcp PR #34, Issue #33)

**`ErrGatewayUpstreamFailure` conflated `rotation_failed` and `upstream_failure`**

**Location:** `copilot-review-mcp/internal/github/gateway_token_source.go`

`gatewayTokenSource.Token()` mapped **all** HTTP 502 responses from the gateway to the same
sentinel `ErrGatewayUpstreamFailure`, without reading the JSON `error` body.

**Resolution:** `gatewayTokenSource.Token()` now parses the JSON `error` field of HTTP 502
responses and emits `ErrGatewayRotationFailed` for `{"error":"rotation_failed"}` and
`ErrGatewayUpstreamFailure` for `{"error":"upstream_failure"}` (or any unrecognised body).
The persistent `ErrGatewayUpstreamFailure` escalation to `AUTH_EXPIRED` after `N` consecutive
failures was also added ([scottlz0310/copilot-review-mcp PR #38](https://github.com/scottlz0310/copilot-review-mcp/pull/38)).
Fixed by [scottlz0310/copilot-review-mcp#33](https://github.com/scottlz0310/copilot-review-mcp/issues/33),
landed in [scottlz0310/copilot-review-mcp PR #34](https://github.com/scottlz0310/copilot-review-mcp/pull/34).

---

## 5. Operator Notes

### 5.1 Log Fields

Structured logs in this repo use the field key `"err"` (not `"error"`) for error values. All
log entries below are emitted with `slog.Error` or `slog.Warn`.

| Log message | Level | Key fields | Meaning |
|---|---|---|---|
| `"upstream error during auth"` | Error | `err`, `path` | GitHub OAuth provider returned 5xx or network failure during token validation; maps to `upstream_error` (503) |
| `"auth failed"` | Warn | `err`, `path` | Token validation failed; maps to `invalid_token` (401) |
| `"internalapi: whoami rotation failed"` | Warn | `subject`, `err` | Refresh rotation failed; maps to `rotation_failed` (502) |
| `"internalapi: whoami lookup failed"` | Warn | `subject`, `err` | Other resolver failure; maps to `upstream_failure` (502) |
| `"internalapi: whoami returned empty access token despite no error"` | Warn | `subject` | Defensive path; maps to `upstream_failure` (502) |

### 5.2 Re-authentication Triggers

A user must complete a fresh OAuth flow when either of the following is observed:

1. The public API returns `invalid_token` — the gateway Bearer token is expired, invalid, or
   not valid for the requested resource (e.g., audience mismatch). Any `invalid_token` response
   requires re-authentication regardless of the specific `error_description`.
2. The internal API returns `subject_not_found` — the user has no cached session on this gateway
   instance (new deployment, cache purge, or the user never authenticated here).
3. The internal API returns `rotation_failed` — token rotation did not yield a fresh access token (may be transient; retry before triggering re-authentication).

Operators can surface the re-authentication URL from the `resource_metadata` parameter in the
`WWW-Authenticate` header of any `401` response.

### 5.3 Configuration Hints

| Symptom | Likely cause | Check |
|---|---|---|
| `loopback_required` (403) on internal API | Caller is not connecting via loopback | Ensure upstream MCP server calls `127.0.0.1:${MCP_GATEWAY_INTERNAL_PORT}`; the listener always binds to `127.0.0.1` only (IPv6 loopback `[::1]` is not supported) |
| `invalid_authorization` (401) on internal API | Mismatched shared secret | `MCP_GATEWAY_INTERNAL_SECRET` in both gateway and upstream server env |
| Persistent `upstream_failure` (502) | Transient resolver or GitHub API failure; or the resolver returned an empty access token | Check GitHub status and retry; inspect gateway logs for resolver errors (`"err"` field) |
| `subject_not_found` (404) after process restart | In-memory subject index starts empty after restart and re-seeds as bearer tokens are validated | Set `MCP_GATEWAY_TOKEN_STORE_PATH` for durable storage so sessions survive restart; the index rebuilds on the first bearer token validation per subject |
| `upstream_error` (503) on every request | GitHub OAuth provider unreachable | Check GitHub status and outbound network access to the OAuth provider (configured via `OAUTH_PROVIDER`, default `github`) |
