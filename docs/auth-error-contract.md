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
gateway intentionally does so for `invalid_request`:

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
| `loopback_required` | 403 | Request originated from a non-loopback address | Check gateway bind config (`gateway.internal_addr`) |
| `invalid_authorization` | 401 | `Authorization: Bearer` secret missing or does not match `MCP_GATEWAY_INTERNAL_SECRET` | Fix the shared secret configuration |
| `invalid_body` | 400 | Malformed JSON, body exceeds 4 KiB, unknown fields, or trailing bytes after the JSON object | Fix the request body |
| `missing_subject` | 400 | `subject` field is present but empty (or whitespace only) | Supply a non-empty subject |
| `subject_not_found` | 404 | No cached token entry exists for the subject — the user has never authenticated through this gateway instance, or their session was purged | Trigger the user to re-authenticate via the public gateway OAuth flow |
| `rotation_failed` | 502 | Token is near expiry, rotation was attempted, but GitHub's token endpoint rejected the refresh | Trigger the user to re-authenticate; the refresh token is no longer valid |
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
GO verdict this was **decided against** — no new error code was added to the codebase.

Instead, the two existing codes cover the concept:

| Code | Why the context is unavailable |
|---|---|
| `subject_not_found` | No token has ever been cached for this subject (user never authenticated on this gateway instance, or cache was purged) |
| `rotation_failed` | A token exists but its refresh token has been revoked or rejected by GitHub |

Both cases require the same corrective action from the caller: trigger the end-user to
re-authenticate via the gateway's public OAuth flow. Callers **SHOULD** treat either code as
"prompt re-authentication."

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
| 401 | `invalid_authorization` | `ErrGatewayUnauthorized` |
| 403 | `loopback_required` | `ErrGatewayLoopbackRequired` |
| 404 | `subject_not_found` | `ErrGatewaySubjectGone` |
| 502 | `rotation_failed` / `upstream_failure` | `ErrGatewayUpstreamFailure` |
| other 4xx | `method_not_allowed` / `invalid_body` / `missing_subject` | `ErrGatewayBadRequest` |

`ErrGatewayUnauthorized`, `ErrGatewayLoopbackRequired`, and `ErrGatewayBadRequest` always
indicate configuration errors; they should never occur in a correctly configured deployment.

> **⚠ Implementation note — HTTP 502 body is not parsed:** `gatewayTokenSource.Token()` maps
> all HTTP 502 responses to `ErrGatewayUpstreamFailure` without reading the JSON `error` field.
> The gateway distinction between `rotation_failed` and `upstream_failure` is therefore
> **invisible to copilot-review-mcp at runtime**. See Gap 3 below.

### 3.2 Watch Manager: Sentinel Errors → `FailureReason`

`copilot-review-mcp/internal/watch/manager.go` classifies polling failures into three
`FailureReason` values:

| `FailureReason` | Meaning |
|---|---|
| `AUTH_EXPIRED` | The auth context expired; the watch cannot continue until the user re-authenticates |
| `GITHUB_ERROR` | A GitHub API error that is not an auth expiry (may be transient) |
| `INTERNAL_ERROR` | Watch setup or database failure |

The manager uses `ghclient.IsAuthError(err)` to distinguish `AUTH_EXPIRED` from `GITHUB_ERROR`.
`IsAuthError` detects HTTP 401 errors from the **GitHub API** — it does **not** recognise gateway
sentinel errors.

**Current (actual) mapping:**

| Sentinel error | `IsAuthError(err)` | `FailureReason` (current) | Semantically correct? |
|---|---|---|---|
| `ErrGatewaySubjectGone` | `false` | `GITHUB_ERROR` | ❌ Should be `AUTH_EXPIRED` — user must re-auth |
| `ErrGatewayUpstreamFailure` *(any 502; body not parsed — see Gap 3)* | `false` | `GITHUB_ERROR` | ⚠️ Indistinguishable at runtime: may need `AUTH_EXPIRED` (rotation_failed) or `GITHUB_ERROR` (upstream_failure) |
| GitHub API 401 | `true` | `AUTH_EXPIRED` | ✅ |
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

`ClassifyGitHubError` is built around GitHub API HTTP status codes. Gateway sentinel errors
(`ErrGatewaySubjectGone`, etc.) do **not** pass through it and therefore have **no defined
`AuthErrorType` mapping** today.

---

## 4. Known Gaps

### Gap 1 — `ErrGatewaySubjectGone` classified as `GITHUB_ERROR` not `AUTH_EXPIRED`

**Location:** `copilot-review-mcp/internal/watch/manager.go`

When a watch's `gatewayTokenSource.Token()` call returns `ErrGatewaySubjectGone` (HTTP 404 from
gateway), `IsAuthError` returns `false` because it only recognises GitHub API 401 patterns.
The watch therefore sets `FailureReason = GITHUB_ERROR`, which gives the user no signal that
re-authentication is required.

**Impact:** Users may see a stale "GitHub error" status instead of a prompt to re-authenticate.
The watch will keep retrying unnecessarily until it times out.

**Recommended fix:** Extend `IsAuthError` (or add a new predicate) in copilot-review-mcp to
recognise `ErrGatewaySubjectGone` and a future `ErrGatewayRotationFailed` sentinel and return
`true`. **This fix depends on Gap 3 being resolved first** — `ErrGatewayUpstreamFailure` must be
split into distinct sentinels before the rotation_failed case can be handled correctly.
Tracked in [scottlz0310/copilot-review-mcp#31](https://github.com/scottlz0310/copilot-review-mcp/issues/31).

### Gap 2 — Gateway sentinel errors have no `AuthErrorType` mapping

**Location:** `copilot-review-mcp/internal/github/classify.go`

When a tool call fails due to a gateway sentinel error, `ClassifyGitHubError` does not produce
an `AuthErrorType`, so `tryAuthResult` cannot build a correctly typed error result. The tool
call response may contain no actionable guidance for the MCP client.

**Recommended fix:** Add explicit handling for gateway sentinel errors in `ClassifyGitHubError`.
Tracked in [scottlz0310/copilot-review-mcp#32](https://github.com/scottlz0310/copilot-review-mcp/issues/32).

| Sentinel | Suggested `AuthErrorType` |
|---|---|
| `ErrGatewaySubjectGone` | `REAUTH_REQUIRED` |
| `ErrGatewayUpstreamFailure` | `TOKEN_REFRESH_FAILED` / `TRANSIENT_UPSTREAM_ERROR` depending on recoverable vs not |
| `ErrGatewayUnauthorized` | `AUTH_REQUIRED` (config error; treat as no-credential state) |

Note: the `ErrGatewayUpstreamFailure` row above reflects the *intended* mapping after Gap 3 is
resolved. Until `rotation_failed` and `upstream_failure` produce distinct sentinels, this
classification cannot be implemented.

### Gap 3 — `ErrGatewayUpstreamFailure` conflates `rotation_failed` and `upstream_failure`

**Location:** `copilot-review-mcp/internal/github/gateway_token_source.go`

`gatewayTokenSource.Token()` maps **all** HTTP 502 responses from the gateway to the same
sentinel `ErrGatewayUpstreamFailure`, without reading the JSON `error` body. The gateway
distinguishes two semantically different 502 conditions:

| Gateway JSON body | Meaning | Required downstream action |
|---|---|---|
| `{"error": "rotation_failed"}` | Refresh token rejected by GitHub | User **must** re-authenticate |
| `{"error": "upstream_failure"}` | Transient resolver / upstream failure | Retry may succeed |

Because the sentinel collapses both, neither `watch/manager.go` nor `ClassifyGitHubError` can
tell "re-auth required" from "retry will probably help." This ambiguity is the root cause that
blocks a clean fix for Gap 1 and Gap 2.

**Recommended fix:** Parse the JSON `error` field of HTTP 502 responses in
`gatewayTokenSource.Token()` and return distinct sentinel errors, for example:

- `ErrGatewayRotationFailed` — for `{"error": "rotation_failed"}`
- `ErrGatewayResolverFailure` — for `{"error": "upstream_failure"}`

Alternatively, define a typed error that carries the gateway error code as a string field so
callers can switch on it without additional sentinels. Once this split exists, Gap 1 and Gap 2
fixes can correctly map `ErrGatewayRotationFailed` → `AUTH_EXPIRED` / `TOKEN_REFRESH_FAILED`.

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

1. The public API returns `invalid_token` with `error_description` containing "expired or invalid"
   — the gateway Bearer token has expired or been revoked.
2. The internal API returns `subject_not_found` — the user has no cached session on this gateway
   instance (new deployment, cache purge, or the user never authenticated here).
3. The internal API returns `rotation_failed` — the GitHub refresh token was rejected.

Operators can surface the re-authentication URL from the `resource_metadata` parameter in the
`WWW-Authenticate` header of any `401` response.

### 5.3 Configuration Hints

| Symptom | Likely cause | Check |
|---|---|---|
| `loopback_required` (403) on internal API | Gateway internal listener accidentally exposed outside loopback | `gateway.internal_addr` (must be `127.0.0.1:<port>` or `[::1]:<port>`) |
| `invalid_authorization` (401) on internal API | Mismatched shared secret | `MCP_GATEWAY_INTERNAL_SECRET` in both gateway and upstream server env |
| Persistent `upstream_failure` (502) | GitHub token store not persisted across restarts | `gateway.token_store_path` points to a writable, durable path |
| `upstream_error` (503) on every request | GitHub OAuth provider unreachable | Check GitHub status and `gateway.provider` network access |
