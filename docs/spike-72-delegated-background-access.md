# Spike #72: Delegated Background Access (Phase B PoC)

**Status**: PoC / spike. Not for production use.
**Refs**: #70 (overall plan), #71 (Phase A: rotation in request path), #72 (this PoC)

## Problem

Phase A (#71) introduced transparent GitHub access-token rotation on the
**client request path** through the gateway. Each inbound proxied request
calls `tryGitHubRotation`, so the bearer presented by an MCP client is
swapped for a fresh one inside the leeway window before it is forwarded.

However, upstream MCP servers (notably `copilot-review-mcp`) run
**background workflows** (a `watch` goroutine for the Copilot review
poller) that bypass the per-request path entirely. They snapshot a
bearer into an `oauth2.StaticTokenSource` at watch-start time and keep
using it for the entire watch lifetime — even after rotation has issued
a new access token.

The Phase A rotation does cache *both* the old and new bearer for the
leeway period, but once the underlying GitHub access token actually
expires, the old bearer presented by the background goroutine starts
returning `401` from GitHub and the watch dies.

## Goal

Provide a **gateway-internal API** that upstream MCP servers can call from
their background goroutines to fetch the **current valid access token for a
known subject**, with the gateway transparently rotating if the token is
close to expiry. The upstream stores no tokens.

This is the Option C ("gateway-managed delegated access") candidate from
#70. The PoC validates the shape; production decisions remain open.

## Non-goals (for this spike)

- Persistent subject→token index across gateway restarts.
- Hardened multi-tenant authorization between multiple upstreams.
- UNIX domain socket / mTLS trust boundary (compared but deferred).
- `copilot-review-mcp` production client implementation (drafted separately).

## Trust boundary: comparison

| Option | Pros | Cons |
|---|---|---|
| **A. UNIX domain socket** | OS-level permission isolation. No secret distribution. No network exposure. | Awkward on Windows; needs sidecar bind-mount in Docker. Two code paths to maintain. |
| **B. loopback + shared secret** (chosen) | Trivial implementation. Cross-platform. Aligns with existing `gateway.key` / env-var patterns. | Secret distribution, rotation, and constant-time comparison must be handled. |
| **C. mTLS** | Strong mutual authentication. Clean cert rotation. | Heavy for a PoC. CA/cert distribution design cost. |
| **D. Hybrid (A + B fallback)** | Platform-optimal. | Doubles the test matrix. Out of PoC scope. |

**Chosen: B**. Rationale: smallest PoC surface that still answers the
"is delegated access useful?" question. Migration to A (Unix socket) is
mostly straightforward later: the listener wiring changes, and the
handler's loopback re-validation needs to become socket-aware (peer
credential / `SO_PEERCRED`-style check instead of `r.RemoteAddr`).

## API

### Endpoint

```
POST /internal/v1/whoami
Host: 127.0.0.1:<INTERNAL_PORT>
Authorization: Bearer <MCP_GATEWAY_INTERNAL_SECRET>
Content-Type: application/json

{ "subject": "alice" }
```

The endpoint is named `whoami` (rather than `token/refresh`) so the
upstream semantics stay "give me the latest valid token", with rotation
policy hidden inside the gateway. This avoids upstream-side
over-rotation and keeps the upstream stateless.

### Response (200)

```json
{
  "access_token": "gho_<rotated>",
  "token_type": "bearer",
  "expires_at": "2026-05-15T20:30:00Z",
  "scopes": ["repo", "read:user"]
}
```

`refresh_token` is intentionally absent: the upstream MUST NOT persist
refresh tokens. The `scopes` field is the gateway's configured scope
list (best-effort identifier for what the access token can do).

### Error responses

| Status | Reason |
|---|---|
| 400 | malformed body, missing `subject`, or trailing data after JSON object |
| 401 | missing/invalid `Authorization` (constant-time compared) |
| 403 | request did not originate from a loopback address |
| 404 | no cached token record for this subject |
| 405 | non-POST method (response includes `Allow: POST`) |
| 502 | provider rotation was required (cached token inside the leeway window) but did not produce a fresh token (`error: "rotation_failed"`) |

## Security model

1. **Listener bind**: 127.0.0.1 / ::1 only. Binding 0.0.0.0 is a startup error.
2. **Defense in depth**: handler re-validates `r.RemoteAddr` is a loopback IP.
3. **Shared secret**:
   - Env var `MCP_GATEWAY_INTERNAL_SECRET`. Must be ≥ 32 chars; shorter is a startup error.
   - Compared with `crypto/subtle.ConstantTimeCompare`.
   - Internal listener is **not started** unless both the secret and port are set (fail-closed).
4. **Body cap**: `http.MaxBytesReader` at 4 KiB.
5. **Logging**: access tokens never appear in logs. Subject is logged in clear (it is the GitHub login, which is already non-sensitive in the gateway's threat model); the upstream listener emits the same structured fields as the public HTTP server.
6. **Limited enumeration resistance**: 404 is returned for "subject not present in the cache". An attacker who has already obtained the shared secret can use timing or status to probe which subjects currently have an active session — this PoC does not attempt to flatten that signal. The mitigation is the shared-secret + loopback boundary, not response-shape obfuscation.

## Subject → token index

Internal lookup design: `auth.Store` gains an **in-memory** secondary
index `subject → []indexEntry{rawToken, expiresAt, providerAccessExpiry}`.

- Updated whenever `CacheToken` is called (sign-up, rotation).
- Pruned lazily on read: expired entries removed.
- **Not persisted to disk** by design — the existing `fileTokenStore`
  hashes tokens precisely so raw tokens never reach disk; we preserve
  that invariant. A gateway restart forces upstream MCP servers to wait
  for the next client request to re-seed the cache.

Trade-off: this is a PoC compromise. A production implementation might
add an encrypted persistent index, or migrate to a model where the
upstream presents its current (possibly stale) token plus subject and
the gateway returns the rotated successor. Documented for follow-up.

## Configuration

| Env var | Required for internal API | Default | Purpose |
|---|---|---|---|
| `MCP_GATEWAY_INTERNAL_SECRET` | Yes | (unset → disabled) | Bearer secret. ≥ 32 chars. |
| `MCP_GATEWAY_INTERNAL_PORT` | Yes | (unset → disabled) | TCP port for the loopback listener. |

Both must be set to enable the API. Either missing → internal listener
is silently not started, with one `slog.Info` line documenting why.

## Rotation policy

On `POST /internal/v1/whoami`:

1. Look up subject. If absent → 404.
2. Pick the entry with the latest `ProviderAccessExpiry`.
3. Delegate to the existing `tryGitHubRotation` code path, which itself
   compares `time.Until(expiry)` against `Handler.githubRefreshLeeway()`
   (the same Phase A policy used on the client request path). If the
   token is still outside the leeway window, the current raw token is
   returned unchanged; otherwise rotation is attempted.
4. If rotation was required (cached token inside the leeway window) but
   did not produce a fresh token — whether the provider returned a
   transient error or a permanent one that cleared the refresh metadata —
   the response is **502 `rotation_failed`**. The gateway never hands
   back a cached bearer that is at or past the rotation threshold; the
   caller is expected to surface the failure to the user.

The Phase B PoC deliberately does **not** introduce a dedicated leeway
constant for delegated background access. It reuses the same GitHub
refresh leeway policy as Phase A (default 5 minutes, overridable via
`Handler.githubRefreshLeeway()`), so a single tunable governs rotation
behaviour across both the client request path and the internal API.
Splitting the leeway out per code path — e.g. a tighter window for
long-running watch goroutines — is intentionally deferred (see Future
work).

## Deployment and limitations

- **Loopback-only by design.** The listener binds 127.0.0.1 / ::1 only,
  so the upstream client must share the gateway's network namespace.
  Concretely:
  - **Same host, bare binary**: works as-is — the upstream connects to
    `127.0.0.1:<INTERNAL_PORT>`.
  - **Docker bridge network**: a container running on the default bridge
    cannot reach the gateway container's loopback. The upstream
    container must be started with `--network=container:<gateway>` (or
    the same compose `network_mode: "service:<gateway>"`), or be
    co-located in the same pod / network namespace.
  - **Reverse proxies**: do not route the internal API through any
    public-facing reverse proxy; the loopback re-validation in the
    handler will reject forwarded requests.
- **No persistence across gateway restart.** The subject index is
  in-memory; after a restart, the upstream watch goroutine will get 404
  for that subject until the user issues a fresh client request that
  re-seeds the cache. The upstream is expected to treat 404 as
  "session-not-yet-ready" rather than a hard failure.
- **Single shared secret.** All upstream consumers share one secret. A
  compromised upstream effectively has the keys to every cached
  subject's access token. Per-upstream identities are listed under
  Future work.

## Future work

- Move trust boundary to Unix socket (Option A) once Linux-only
  upstream sidecars are the canonical deployment.
- Add a `POST /internal/v1/token/refresh` that *forces* rotation
  regardless of expiry (separate semantics from whoami).
- Split the refresh leeway per code path / make it configurable —
  long-running watch goroutines may want a tighter window than the
  Phase A client request path. Today both reuse `Handler.githubRefreshLeeway()`.
- Persistent encrypted subject index.
- Per-upstream secret/identity (today: one shared secret for all upstreams).
- Telemetry / metrics for delegated-access call rate vs rotation rate.

## Open questions

- Should the gateway emit a structured event (audit log) per internal
  call? Probably yes for production; out of PoC scope.
- Should `scopes` reflect the actual GitHub-granted scopes rather than
  the configured request scopes? Requires storing scopes on the
  `TokenRecord`, which is a separate change.
