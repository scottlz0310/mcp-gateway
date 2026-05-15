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
gateway's own cache TTL (so MCP requests presenting either bearer continue
to validate inside the gateway), but the underlying **GitHub-side access
token validity** is independent of that cache: once the original GitHub
access token actually expires, the old bearer presented by the background
goroutine starts returning `401` from GitHub and the watch dies.

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
| 502 | upstream resolver failed for a non-rotation reason, or returned an empty access token despite reporting success (`error: "upstream_failure"`) |

## Security model

1. **Listener bind**: 127.0.0.1 (IPv4 loopback) only in the current PoC. Binding 0.0.0.0 / a non-loopback interface is a startup error. IPv6 loopback (`::1`) is not bound today; adding it is straightforward (`net.Listen` on `[::1]:<port>`) but out of PoC scope.
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
index `subject → []indexEntry{rawToken, expiresAt}`. The
authoritative `ProviderAccessExpiry` is read from the underlying
`TokenRecord` at lookup time so the index stays minimal.

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

### Prerequisite for rotating GitHub tokens

The internal API only triggers transparent rotation when the existing
GitHub refresh flag is on. Set it together with the internal API env
vars when you expect expiring GitHub OAuth tokens:

| Setting | Required for rotation | Effect |
|---|---|---|
| `MCP_GATEWAY_GITHUB_REFRESH_ENABLED` / `gateway.github_refresh_enabled` | Yes (for rotating tokens) | Persists provider refresh metadata and lets `tryGitHubRotation` actually call the GitHub refresh endpoint. Defaults to **false**. |

If the flag is off, `/internal/v1/whoami` still works but only ever
returns the cached access token — useful for classic non-expiring PATs,
but **not** for expiring OAuth tokens, where the gateway will keep
handing back the same (eventually dead) bearer.

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

- **Loopback-only by design.** The listener binds 127.0.0.1 only (IPv4
  loopback). The request handler additionally accepts `::1` for
  defense-in-depth, but no IPv6 listener is started in this PoC, so
  upstream clients must connect over IPv4. The upstream must share the
  gateway's network namespace.
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

## Known limitations (PoC scope)

The Copilot review on PR #76 surfaced two rotation-correctness gaps
that are **not** addressed in this PoC because each requires a design
change larger than the PoC envelope. They are accepted as risks because
the loopback + shared-secret trust boundary keeps the blast radius
inside the host, and because background watch goroutines tolerate
transient 401s by re-issuing the delegated call. They are tracked
under Future work and should be resolved before this API leaves PoC
status.

Note that the **temporal** blast radius depends on which token store is
configured:

- In-memory store (default for short-lived dev): bounded by
  `cfg.CacheTTL` (a few minutes).
- Persistent store (`auth.NewHandler` with a non-nil TokenStore):
  bounded by `cfg.ExpiresIn` — **90 days by default** — because that
  value drives both the issued session expiry and the cache TTL
  applied to saved token records. A dead bearer / old-bearer
  preference can therefore persist for days unless the operator
  invalidates the entry manually or the user re-authenticates.

1. **Dead bearer after permanent rotation failure.** When
   `runGitHubRotation` hits a *permanent* failure (`bad_refresh_token`
   or an upstream response that reports success but returns an empty
   `access_token`) it calls `ClearProviderRefresh` on the token entry.
   The next `/internal/v1/whoami` call then finds no provider-refresh
   metadata and falls into the lenient "no rotation contract" branch,
   which returns the cached bearer with `200`. That bearer is almost
   certainly already invalid on GitHub's side. Note that *transient*
   upstream failures (5xx, network errors surfaced as
   `auth.UpstreamError`) do **not** trigger `ClearProviderRefresh`;
   they return `502 upstream_failure` with rotation metadata preserved
   so the next call still takes the rotation path
   (`action=retry_next`). The dead-bearer pitfall therefore applies
   only to the permanent-failure subset. **Recovery does not happen
   by simply re-issuing the delegated call on the next polling cycle**:
   subsequent calls keep taking the same lenient branch and return the
   same dead bearer until the underlying token-store/index TTL expires
   (see the per-store bounds above) or the user re-authenticates.
   Background callers will observe a `401` from GitHub on every use
   and the gateway has no in-band recovery path. Proper fix: persist a
   `RotationFailed` (or equivalent) flag on `TokenRecord` and surface
   `ErrRotationFailed` on the next call.

2. **Old/new bearer tie-break in `LatestBySubject`.** On successful
   rotation, `runGitHubRotation` updates the *old* token entry's
   `ProviderAccessExpiry` to the same value as the new entry (so a
   client that keeps presenting the old bearer can still be rotated on
   the next request). `LatestBySubject` walks the subject-index slice
   in deterministic insertion order and ranks candidates by strict
   `.After(...)`; when both entries carry an equal `ProviderAccessExpiry`
   the strict comparison fails for the later-visited entry, so the
   *first-inserted* (i.e. older) bearer keeps the lead and is returned
   — even though only the *new* bearer is actually valid against
   GitHub's original access token. The hazard is therefore the
   insertion-order + equal-expiry combination, not map iteration
   non-determinism. Proper fix: break ties in favour of the newest
   index entry, or track the currently-active access token explicitly
   on the rotation chain.

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
