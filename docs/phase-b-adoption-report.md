# Phase B — Delegated Background Access: PoC-to-Production Adoption Report

> **Verdict: GO — adopt Phase B implementation as-is, with noted limitations.**

---

## 1. Background

Issue #70 identified that `copilot-review-mcp` snapshots a GitHub OAuth bearer at watch-start time
and holds it for up to two hours of background polling. Short-lived tokens (GitHub App installation
tokens, expiring OAuth App tokens) expire mid-watch and return `FailureReasonAuthExpired`. Phase A
(PR #71) added gateway-side rotation on inbound requests, but could not reach already-running watch
goroutines. Phase B adds a pull-model internal API so the upstream MCP server can ask the gateway
for a fresh token whenever it needs one — without storing credentials itself.

---

## 2. What Phase B Implemented (PR #76 + Issue #77)

### 2.1 Internal API (`/internal/v1/whoami`)

| Attribute | Value |
|---|---|
| Transport | HTTP, loopback-only (`127.0.0.1`; configurable via `gateway.internal_addr`) |
| Auth | `MCP_GATEWAY_INTERNAL_SECRET` shared secret, `Authorization: Bearer <secret>` |
| Method / path | `POST /internal/v1/whoami` |
| Request body | `{"subject": "<github_login>"}` |
| Response | `{"access_token": "...", "provider_access_expiry": "...", "scopes": "..."}` |
| Implementation | `internal/internalapi/` package, separated from the public gateway mux |

The shared secret is compared with `subtle.ConstantTimeCompare` to prevent timing attacks.
The server binds exclusively on the loopback interface; no TLS is required for same-host deployments.

### 2.2 `EnsureFreshAccessTokenForSubject` (handler layer)

The core delegated-access primitive. Called by the `/internal/v1/whoami` handler:

1. `LatestBySubject(subject)` — finds the most recently rotated token for the given GitHub login in
   the in-memory subject index.
2. If the cached expiry is within the leeway window and a refresh token is available, triggers
   `runGitHubRotation` (deduplicated via `singleflight`).
3. Returns the resulting `DelegatedAccessResult{AccessToken, ProviderAccessExpiry, Scopes}` or a
   typed error (`ErrSubjectNotFound`, `ErrRotationFailed`).

### 2.3 Subject Index (`Store.subjectIndex`)

In-memory map from GitHub `login` → `[]subjectIndexEntry`. Updated every time a token is cached
(`CacheToken`) or a rotation completes (`RecordProviderRefresh`). Enables O(n) scan over all tokens
for a subject to pick the best one.

---

## 3. Correctness Gaps Closed (Issue #77)

Three gaps were identified during the PR #76 Copilot review cycle:

### Gap 1 — Concurrent double-rotation → `noOp` (✅ Already fixed in PR #76)

The `singleflight` group deduplicates concurrent `EnsureFreshAccessTokenForSubject` calls for the
same raw token. When multiple goroutines race, the leader performs rotation; followers observe the
updated record and return `rotationResult{noOp: true}` because the new expiry is already outside
the leeway window. No code change needed.

### Gap 2 — Permanent rotation failure → dead bearer via lenient branch (✅ Fixed in Issue #77)

**Root cause**: `runGitHubRotation` called `ClearProviderRefresh(token)` on permanent failures
(`bad_refresh_token`, revoked credentials). This zeroed `ProviderRefreshToken` and
`ProviderAccessExpiry`. The *next* call to `EnsureFreshAccessTokenForSubject` found the token in
the lenient branch (no refresh metadata → no rotation attempted) and returned the dead bearer with
HTTP 200.

**Fix**:
- Added `rotationFailed map[string]struct{}` (keyed by `tokenKey` SHA-256 hash) to `Store`.
- `MarkRotationPermanentlyFailed(token)` calls `ClearProviderRefresh` **and** sets the flag.
- `IsRotationPermanentlyFailed(token) bool` exposes the flag.
- `runGitHubRotation` now calls `MarkRotationPermanentlyFailed` on permanent failures (non-upstream
  errors, empty access token). `ErrRefreshNotSupported` still calls only `ClearProviderRefresh`
  because a classic PAT is not failed — it is simply not rotatable.
- The lenient branch in `EnsureFreshAccessTokenForSubject` checks `IsRotationPermanentlyFailed`
  before returning the token; returns `ErrRotationFailed` instead.

**Previously a caveat, now resolved**: `rotationFailed` was in-memory only. After a gateway restart the
flag would be absent, and if the token remained in a file-backed store `ValidateToken` would call
`RefreshSubjectIndex` on the next cache hit, re-seeding the subject index. The lenient branch would then
return the dead bearer without re-setting the flag.

**Fix (Issue #77, Thread 1 response)**: `MarkRotationPermanentlyFailed` now:
1. Persists a `RotationPermanentlyFailed` flag in the token store entry (flushed to disk for file-backed stores).
2. Removes the token from the subject index immediately via `removeSubjectIndexEntry`.
3. Sets the in-memory `rotationFailed` flag for belt-and-suspenders within the same process.

`ValidateToken` now skips `RefreshSubjectIndex` for records with `RotationPermanentlyFailed=true`. After
a gateway restart:
- `ValidateToken("at")` → record found with flag set → subject index NOT re-seeded.
- `EnsureFreshAccessTokenForSubject` → `LatestBySubject` returns `ok=false` → `ErrSubjectNotFound`.
  Client must re-authenticate. The dead bearer is never returned.

### Gap 3 — `LatestBySubject` tie-break on equal expiry (✅ Fixed in Issue #77)

**Root cause**: `runGitHubRotation` writes the same `newAccessExpiry` to both the new token and the
old token via `persistProviderRefresh`. Both subject index entries then have identical
`ProviderAccessExpiry`. The original strict `.After()` condition kept the *first-encountered*
entry, which is the old token (appended earlier to the slice).

**Fix**: Changed ranking condition to:
```go
!foundRotatable ||
rec.ProviderAccessExpiry.After(bestRec.ProviderAccessExpiry) ||
(foundRotatable && rec.ProviderAccessExpiry.Equal(bestRec.ProviderAccessExpiry))
```
Forward iteration + "update on equal" → the last-appended entry (the new token) wins the tie.
No new struct fields required.

---

## 4. Security Model Assessment

| Property | Assessment |
|---|---|
| **Network exposure** | Loopback-only. Not reachable from external networks. ✅ |
| **Authentication** | Shared secret, constant-time comparison, `Authorization: Bearer`. Adequate for same-host IPC. ✅ |
| **Secret storage** | Env var (`MCP_GATEWAY_INTERNAL_SECRET`). Standard 12-factor practice. ✅ |
| **Token in transit** | Cleartext loopback (127.0.0.1). Acceptable for same-host; loopback traffic is not observable from other hosts. ✅ |
| **Token at rest** | Bearer tokens are never written to disk by the delegated-access path. In-memory only. ✅ |
| **Subject spoofing** | Any process on the same host that knows the secret can request a token for any cached subject. Acceptable for a trusted co-located MCP server; not suitable for multi-tenant environments. ⚠️ |
| **Secret rotation** | Requires gateway restart. Low operational overhead for single-binary deployments. ✅ |
| **Multi-host / container isolation** | Not supported. If gateway and MCP server run in different containers, the loopback approach does not work without additional networking (host-network mode, mTLS, etc.). ⚠️ |

**Overall**: The security model is appropriate for same-host deployments (bare metal, single Docker
host, or `network_mode: host` compose). Multi-host or Kubernetes deployments require Unix-socket or
mTLS for the internal API — this is deferred to a future phase.

---

## 5. Remaining Known Limitations

| # | Limitation | Impact | Mitigation / Future |
|---|---|---|---|
| L1 | Subject index is in-memory only | After restart, delegated access returns `ErrSubjectNotFound` until the subject re-authenticates via the public gateway | Users must re-authenticate after gateway restart (same as current behavior) |
| L2 | `RotationPermanentlyFailed` flag persistence requires file-backed store | In-memory-only mode: after restart, one extra rotation attempt is made before the flag is re-set | Use `token_store_path` (file-backed) for durable flag; in durable mode, `ValidateToken` skips `RefreshSubjectIndex` post-restart → `ErrSubjectNotFound` returned |
| L3 | Scopes are gateway-wide (`gateway.github_scopes`) | Cannot grant per-token or per-subject scope subsets | Fine-grained scopes deferred |
| L4 | `expires_in` not always sent by GitHub | `ProviderAccessExpiry` may be zero if GitHub omits the field | Rotation falls back to leeway-based heuristic; behaviour unchanged from Phase A |
| L5 | Multi-host deployments unsupported | Loopback-only bind; container isolation may block internal API | Unix socket or mTLS support deferred |
| L6 | Classic PAT tokens never rotate | `ErrRefreshNotSupported` → `ClearProviderRefresh`; PAT remains usable but expiry unknown | Acceptable; PATs are long-lived by design |

---

## 6. Test Coverage Added (Issue #77)

| Test | File | What it verifies |
|---|---|---|
| `TestEnsureFreshAccessTokenForSubject_PermanentFailureLenientBranchReturnsError` | `delegated_access_test.go` | Gap 2: second call after permanent failure returns `ErrRotationFailed`, not dead bearer |
| `TestLatestBySubjectTieBreaksOnInsertionOrder` | `subject_index_test.go` | Gap 3: equal-expiry tie-break returns the most recently registered token |

All 8 pre-existing Phase B delegated-access tests continue to pass. Total auth package test suite:
`go test ./internal/auth/... -count=1` → green.

---

## 7. Go / No-Go Recommendation

**Recommendation: GO — promote Phase B to production-ready.**

### Justification

1. **Correctness**: All three gaps identified in the PR #76 review are now closed. The rotation
   lifecycle is correct under the full concurrency model (singleflight, duplicate calls, permanent
   failures, tie-breaking).
2. **Security**: The loopback + shared secret model is well-established for same-host IPC and has
   no known vulnerabilities within its intended deployment topology.
3. **Test coverage**: Both new fix paths are covered by regression tests. Existing tests remain
   green. The implementation is safe to ship.
4. **Operational simplicity**: No new infrastructure required for same-host deployments. Config
   surface is a single env var and a single `gateway.internal_addr` option.
5. **Known limitations are acceptable**: L1–L6 are all either low-impact or deferred with clear
   upgrade paths. None block the primary use case (preventing auth-expired failures in long-running
   background watches on the same host).

### Conditions for re-evaluation

- If `copilot-review-mcp` moves to a multi-container deployment, revisit L5 (Unix socket / mTLS).
- If per-subject scope restrictions are required, revisit L3 (fine-grained scopes).
- If gateway restarts are frequent (< 2-hour interval in watch-heavy deployments), revisit L1
  (persistent subject index).

---

## 8. Related Issues and PRs

| Ref | Description | Status |
|---|---|---|
| Issue #70 | Auth lifecycle mismatch spike | ✅ Closed (spike complete) |
| Issue #72 | Phase B design + PoC | ✅ Closed (PR #76 merged) |
| PR #76 | Phase B PoC implementation | ✅ Merged |
| Issue #77 | Phase B rotation correctness gaps (Gap 2 + Gap 3) | ✅ Fixed in this PR |
| Issue #73 | Phase C: structured error contract | 🟡 Open (blocked on Phase B adoption decision — now unblocked) |
