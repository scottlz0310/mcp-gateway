# Configuration Reference

This page is the detailed configuration reference for mcp-gateway. The README
keeps only the quick-start path and links here for full operational settings.

## Required Startup Inputs

mcp-gateway needs all of the following before it can run in normal mode:

| Requirement | Environment source | `config.yaml` source |
|-------------|--------------------|----------------------|
| OAuth client ID | `OAUTH_CLIENT_ID` (legacy: `GITHUB_MCP_CLIENT_ID`) | `auth.github_client_id` |
| OAuth client secret | `OAUTH_CLIENT_SECRET` for first-start seeding (legacy: `GITHUB_MCP_CLIENT_SECRET`) | `auth.github_client_secret` |
| At least one route | `ROUTE_<NAME>` | `routes:` |

If any required value is missing, the gateway enters setup mode and prints a
one-time `/setup` URL to stdout.

## Precedence

Configuration is resolved in this order:

| Setting | Precedence |
|---------|------------|
| OAuth provider | `OAUTH_PROVIDER` > `auth.provider` > `github` (default) |
| OAuth client ID | `OAUTH_CLIENT_ID` > deprecated `GITHUB_MCP_CLIENT_ID` > `auth.client_id` > `auth.github_client_id` |
| OAuth client secret | encrypted/plain `auth.client_secret` > encrypted/plain `auth.github_client_secret` > non-empty `OAUTH_CLIENT_SECRET` > deprecated `GITHUB_MCP_CLIENT_SECRET` used to seed `config.yaml` |
| Routes | `ROUTE_<NAME>` env vars > `routes:` in `config.yaml` > deprecated `GITHUB_MCP_UPSTREAM_URL` fallback |
| Public URL | `MCP_GATEWAY_PUBLIC_URL` > deprecated `MCP_GATEWAY_BASE_URL` > `gateway.public_url` > deprecated `gateway.base_url` > default |
| Bind address | `MCP_GATEWAY_BIND_ADDR` > `gateway.bind_addr` > `127.0.0.1:<resolved-port>` |
| OAuth scopes | `OAUTH_SCOPES` > deprecated `GITHUB_MCP_OAUTH_SCOPES` > `gateway.oauth_scopes` > `repo,user` |
| Trusted proxies | `MCP_GATEWAY_TRUSTED_PROXIES` > `gateway.trusted_proxies` > none |
| Token audience strict mode | `MCP_GATEWAY_TOKEN_AUDIENCE_STRICT` > `gateway.token_audience_strict` > `false` |
| GitHub refresh token rotation | `MCP_GATEWAY_GITHUB_REFRESH_ENABLED` > `gateway.github_refresh_enabled` > `false` |
| Allowed redirect hosts | `MCP_GATEWAY_ALLOWED_REDIRECT_HOSTS` > `gateway.allowed_redirect_hosts` > `localhost, 127.0.0.1, vscode.dev, antigravity.google` (default) |
| Allowed redirect schemes | `MCP_GATEWAY_ALLOWED_REDIRECT_SCHEMES` > `gateway.allowed_redirect_schemes` > `antigravity, antigravity-insiders` (default) |

The OAuth client secret is intentionally special: once `config.yaml` contains a
secret, `OAUTH_CLIENT_SECRET` / `GITHUB_MCP_CLIENT_SECRET` are ignored except
during first-start seeding.

When the legacy `GITHUB_MCP_*` variables are observed at startup, the gateway
emits a one-time `slog.Warn` per legacy variable. If both the canonical
`OAUTH_*` and its legacy counterpart are set, the canonical wins and a warning
is logged that the legacy is ignored.

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `OAUTH_PROVIDER` | `github` | OAuth provider kind. Currently `github` and `oidc` are supported. |
| `OAUTH_CLIENT_ID` | none | OAuth client ID. Required unless `auth.client_id` or `auth.github_client_id` is set. Supersedes `GITHUB_MCP_CLIENT_ID`. |
| `OAUTH_CLIENT_SECRET` | none | OAuth client secret. Used to seed encrypted `config.yaml` when no config secret exists. Supersedes `GITHUB_MCP_CLIENT_SECRET`. |
| `OAUTH_SCOPES` | `repo,user` | OAuth scopes requested by the gateway. Supersedes `GITHUB_MCP_OAUTH_SCOPES`. |
| `OAUTH_ISSUER_URL` | none | OIDC issuer URL (required when `OAUTH_PROVIDER=oidc`). |
| `OAUTH_AUDIENCE` | none | OIDC audience (optional when `OAUTH_PROVIDER=oidc`). Reserved for future local JWT validation; currently unused/no-op in UserInfo validation. |
| `GITHUB_MCP_CLIENT_ID` | none | **Deprecated** — use `OAUTH_CLIENT_ID`. Still accepted with a startup warning. |
| `GITHUB_MCP_CLIENT_SECRET` | none | **Deprecated** — use `OAUTH_CLIENT_SECRET`. Still accepted with a startup warning. |
| `GITHUB_MCP_OAUTH_SCOPES` | none | **Deprecated** — use `OAUTH_SCOPES`. Still accepted with a startup warning. |
| `ROUTE_<NAME>` | none | Route definition in `<prefix>|<upstream_url>[|auth=none]` form. At least one route is required unless configured in `config.yaml`. |
| `MCP_CONFIG_FILE` | OS state dir¹ `/config.yaml` | Path to persisted YAML configuration. |
| `MCP_GATEWAY_KEY_PATH` | OS state dir¹ `/gateway.key` | Path to the age X25519 identity used to encrypt `auth.github_client_secret`. |
| `MCP_GATEWAY_MASTER_KEY` | none | Optional deterministic key seed. Use 32+ random bytes encoded as a string, for example `openssl rand -base64 32`. Used only when creating `gateway.key`. |
| `MCP_MASTER_KEY` | none | Legacy alias for `MCP_GATEWAY_MASTER_KEY`. |
| `MCP_GATEWAY_PUBLIC_URL` | `http://127.0.0.1:<port>` | Canonical client-visible URL used for OAuth callbacks, discovery metadata, and Protected Resource Metadata. |
| `MCP_GATEWAY_BIND_ADDR` | `127.0.0.1:<port>` | TCP listener address. Use `0.0.0.0:<port>` inside Docker when publishing ports. |
| `MCP_GATEWAY_PORT` | `8080` | Port used to derive default `public_url` and `bind_addr` when those settings are not explicit. |
| `MCP_GATEWAY_BASE_URL` | none | Deprecated alias for `MCP_GATEWAY_PUBLIC_URL`. Emits a startup warning when set. |
| `MCP_GATEWAY_TRUSTED_PROXIES` | none | Comma-separated CIDR list for immediate reverse proxies whose `X-Forwarded-*` headers are trusted. |
| `MCP_GATEWAY_TOKEN_STORE_PATH` | OS state dir¹ `/tokens.json` | Persistent token store path. Set to an empty value to disable persistence. Docker deployments override this via env var. |
| `MCP_GATEWAY_AUTH_AUDIT_LOG_PATH` | OS audit dir² | OAuth 監査 JSON Lines の絶対 path。相対 path と Git worktree 配下は起動時に拒否される。 |
| `MCP_GATEWAY_AUTH_AUDIT_MAX_SIZE_MB` | `10` | 監査ログ1ファイルの最大サイズ（MiB）。 |
| `MCP_GATEWAY_AUTH_AUDIT_MAX_BACKUPS` | `5` | 保持するローテーション済み監査ログの最大数。 |
| `MCP_GATEWAY_AUTH_AUDIT_MAX_AGE_DAYS` | `30` | ローテーション済み監査ログの最大保持日数。 |
| `MCP_GATEWAY_TOKEN_AUDIENCE_STRICT` | `false` | Reject legacy tokens that have no recorded audience metadata. Leave disabled during migration. |
| `MCP_GATEWAY_GITHUB_REFRESH_ENABLED` | `false` | Enable transparent rotation of expiring GitHub user access tokens. Safe to leave on when token expiration is disabled on the GitHub App; the rotation path stays dormant unless GitHub returns `refresh_token` + `expires_in`. See [GitHub OAuth Refresh Token Rotation](#github-oauth-refresh-token-rotation). |
| `MCP_GATEWAY_ALLOWED_REDIRECT_HOSTS` | none | Comma-separated list of hostnames permitted in OAuth redirect_uris. When set, replaces the built-in default list entirely. |
| `MCP_GATEWAY_ALLOWED_REDIRECT_SCHEMES` | none | Comma-separated list of custom URL schemes (RFC 8252) permitted in OAuth redirect_uris in addition to `http` and `https`. When set, replaces the built-in default list entirely. Defaults to `antigravity,antigravity-insiders`. |
| `LOG_LEVEL` | `info` | JSON log level: `debug`, `info`, `warn`, or `error`. |
| `SESSION_TTL_MIN` | `10` | OAuth authorization session lifetime in minutes. |
| `TOKEN_CACHE_TTL_MIN` | `30` | In-memory validation cache TTL in minutes. Used when token persistence is disabled. |
| `TOKEN_EXPIRES_IN_SEC` | `7776000` | Token lifetime advertised to clients and persistent token entry TTL. Default is 90 days. |
| `GITHUB_MCP_UPSTREAM_URL` | none | Deprecated single-upstream fallback when no `ROUTE_*` or `routes:` entries exist. |

¹ **OS state directory** — resolved by `gatewayStateDir()` at startup:

| OS | Default state directory |
|----|------------------------|
| Windows | `%LOCALAPPDATA%\mcp-gateway\` |
| macOS | `~/Library/Application Support/mcp-gateway/` |
| Linux / other | `$XDG_STATE_HOME/mcp-gateway/` → `~/.local/state/mcp-gateway/` |
| Docker (official image) | `/data/mcp-gateway/` (via `XDG_STATE_HOME=/data`) |

The directory is created automatically on startup (`MkdirAll 0700`). Docker and
other containerised deployments should always pin paths explicitly via environment
variables; the OS default applies to bare-metal installations only.

² **OS audit log directory** — resolved independently by `authaudit.defaultPath()`
(separate from `gatewayStateDir()`):

| OS | Default audit log path |
|----|------------------------|
| Windows | `%LOCALAPPDATA%\mcp-gateway\logs\auth-audit.jsonl` |
| macOS | `~/Library/Logs/mcp-gateway/auth-audit.jsonl` |
| Linux / other | `$XDG_STATE_HOME/mcp-gateway/logs/auth-audit.jsonl` → `~/.local/state/mcp-gateway/logs/auth-audit.jsonl` |
| Docker (official image) | `/data/mcp-gateway/logs/auth-audit.jsonl` (via `XDG_STATE_HOME=/data`) |

`MCP_GATEWAY_MASTER_KEY` is checked as the byte length of the supplied string
after trimming whitespace. A base64 string generated with `openssl rand -base64
32` is accepted as-is; the gateway does not base64-decode it before validation.

## `config.yaml`

Example:

```yaml
auth:
  github_client_id: "Ov23liXXXX"
  github_client_secret: "ENC[age:]<base64-ciphertext>"

gateway:
  public_url: "http://127.0.0.1:8080"
  bind_addr: "127.0.0.1:8080"
  port: "8080"
  oauth_scopes: "repo,user"
  trusted_proxies:
    - "127.0.0.1/32"
  token_audience_strict: false
  allowed_redirect_hosts:
    - "antigravity.google"

routes:
  - name: github
    prefix: /mcp/github
    upstream: http://github-mcp:8082
  - name: public
    prefix: /public
    upstream: http://public-svc:8083
    no_auth: true

setup:
  completed: true
```

### YAML Keys

| Key | Description |
|-----|-------------|
| `auth.provider` | OAuth provider kind (`github` or `oidc`). |
| `auth.client_id` | Generic OAuth client ID. |
| `auth.client_secret` | Generic OAuth client secret. May be encrypted as `ENC[age:]...`. |
| `auth.github_client_id` | GitHub App client ID. |
| `auth.github_client_secret` | GitHub App client secret. May be encrypted as `ENC[age:]...`. |
| `auth.oidc_issuer_url` | OIDC issuer URL. |
| `auth.oidc_audience` | OIDC audience. Reserved for future local JWT validation; currently unused/no-op in UserInfo validation. |
| `gateway.public_url` | Canonical public URL visible to OAuth and MCP clients. |
| `gateway.bind_addr` | TCP listener address. |
| `gateway.base_url` | Deprecated alias for `gateway.public_url`. |
| `gateway.port` | Port used when deriving defaults. |
| `gateway.oauth_scopes` | OAuth scopes requested from GitHub. |
| `gateway.trusted_proxies` | CIDR list for trusted reverse proxy peers. |
| `gateway.token_audience_strict` | Strict legacy-token audience enforcement. |
| `gateway.github_refresh_enabled` | Enable transparent GitHub OAuth access token rotation; see [GitHub OAuth Refresh Token Rotation](#github-oauth-refresh-token-rotation). |
| `gateway.allowed_redirect_hosts` | YAML list of hostnames permitted in OAuth redirect_uris. When set, replaces the built-in default list entirely. |
| `gateway.allowed_redirect_schemes` | YAML list of custom URL schemes (RFC 8252) permitted in OAuth redirect_uris in addition to `http` and `https`. When set, replaces the built-in default list entirely. Defaults to `["antigravity", "antigravity-insiders"]`. |
| `routes[].name` | Route name. Must be non-empty. |
| `routes[].prefix` | URL path prefix. Must start with `/`; trailing slashes are trimmed except for `/`. |
| `routes[].upstream` | Absolute `http` or `https` upstream URL. |
| `routes[].no_auth` | When true, skips Bearer validation for this route. |
| `setup.completed` | Setup wizard state written by the gateway. Operators normally do not edit it directly. |

Unknown YAML fields and comments are not preserved when the gateway rewrites
`config.yaml` during secret migration or setup completion.

## Route Configuration

Environment routes use:

```bash
ROUTE_<NAME>=<prefix>|<upstream_url>
```

Examples:

```bash
ROUTE_GITHUB=/mcp/github|http://github-mcp:8082
ROUTE_REVIEW_RAVEN=/mcp/review-raven|http://review-raven:8083
```

Rules:

- `NAME` must not be empty.
- `prefix` must start with `/`.
- `prefix` must not contain whitespace.
- `upstream_url` must be an absolute `http` or `https` URL.
- Duplicate prefixes are rejected.
- Routes are sorted by longest prefix first.

Disable auth for a route by adding `|auth=none`:

```bash
ROUTE_PUBLIC=/public|http://public-svc:8083|auth=none
```

Use `auth=oauth` only when you need to be explicit; it is the default.

## Secret Encryption

The gateway stores `auth.github_client_secret` encrypted at rest with
`filippo.io/age` X25519.

Startup behavior:

1. Load or generate `gateway.key` from `MCP_GATEWAY_KEY_PATH`.
2. Load `config.yaml` from `MCP_CONFIG_FILE`.
3. Resolve the secret:
   - `ENC[age:]...` in config: decrypt and use.
   - Plaintext in config: encrypt, rewrite config, and use.
   - No config secret plus `OAUTH_CLIENT_SECRET` (or legacy `GITHUB_MCP_CLIENT_SECRET`): encrypt, save to config, and use.
   - No source: fail startup.

Key generation priority:

| Condition | Result |
|-----------|--------|
| `gateway.key` exists | Load and use it; `MCP_GATEWAY_MASTER_KEY` is ignored. |
| `gateway.key` absent and `MCP_GATEWAY_MASTER_KEY` set | Derive the X25519 identity with HKDF-SHA256 and save it. |
| `gateway.key` absent and no master key | Generate a random X25519 identity and save it. |

Secrets and key material are not logged. A corrupt, empty, or unreadable
`gateway.key` is fatal; it is not regenerated automatically.

## Token Persistence

By default, validated token state is stored in `{state-dir}/tokens.json` (see
the OS state directory table in the [Environment Variables](#environment-variables)
section above). Docker deployments override this via `MCP_GATEWAY_TOKEN_STORE_PATH`
in `docker-compose.yml`. To point to an explicit path:

```bash
MCP_GATEWAY_TOKEN_STORE_PATH=/var/lib/mcp-gateway/tokens.json
```

Set the variable to an empty value to disable persistence:

```bash
MCP_GATEWAY_TOKEN_STORE_PATH=
```

The primary token store:

- Loads token-to-identity mappings on startup.
- Saves mappings after successful authentication.
- Sweeps expired entries every minute.
- Writes with mode `0600` where supported.
- Stores SHA-256-hashed token keys, not raw token values.

When token persistence is enabled, refresh tokens are stored in
`<path>.refresh`. That file stores hashed refresh token keys and the associated
access token value in plaintext because the gateway must re-present the access
token to GitHub during refresh. Treat it as sensitive data.

When `MCP_GATEWAY_GITHUB_REFRESH_ENABLED=true` (or `gateway.github_refresh_enabled: true`),
the gateway also stores the GitHub OAuth **refresh token** in `tokens.json`
(the primary store, not the `.refresh` sibling) so rotation continues to work
across restarts. The refresh token is written as plaintext because the
gateway must replay it to GitHub's `/login/oauth/access_token` endpoint.

Operational implications of refresh-token persistence:

- A reader of `tokens.json` can hijack the logged-in user's GitHub session for
  the lifetime of the refresh token. With GitHub's expiring-user-token
  configuration this is typically **six months** unless the user revokes the
  authorization or the GitHub App is reconfigured.
- Backups of `tokens.json` carry the same risk. Encrypt backup volumes at
  rest, or exclude `tokens.json` and `tokens.json.refresh` from broad backup
  scopes.
- Container images and snapshots should not bake either file in.
- If you do not need rotation across restarts, leave `github_refresh_enabled`
  off; the refresh token is then never written to disk.

## Reverse Proxy Headers

When TLS terminates before mcp-gateway:

```bash
MCP_GATEWAY_PUBLIC_URL=https://mcp.example.com
MCP_GATEWAY_BIND_ADDR=127.0.0.1:8080
MCP_GATEWAY_TRUSTED_PROXIES=127.0.0.1/32,10.0.0.0/8
```

Only requests whose immediate peer IP is in `trusted_proxies` may affect:

| Header | Effect |
|--------|--------|
| `X-Forwarded-Proto` | Sets the request scheme when the value is `http` or `https`. |
| `X-Forwarded-Host` | Sets `r.Host` after basic host validation. |
| `X-Forwarded-For` | Sets `r.RemoteAddr` to the rightmost valid IP supplied by the trusted proxy. |

Untrusted forwarded headers are stripped before auth, setup checks, access logs,
and proxying run.

## OAuth And MCP Endpoints

| Path | Method | Description |
|------|--------|-------------|
| `/.well-known/oauth-authorization-server` | GET | RFC 8414 authorization server metadata. |
| `/.well-known/oauth-protected-resource` | GET | Gateway-wide RFC 9728 Protected Resource Metadata. Also covers root-prefix routes. |
| `/.well-known/oauth-protected-resource/<prefix>` | GET | Per-route Protected Resource Metadata for authenticated non-root routes, e.g. `/.well-known/oauth-protected-resource/mcp/github`. |
| `/authorize` | GET | OAuth 2.0 authorization endpoint. |
| `/callback` | GET | GitHub OAuth callback. |
| `/device_authorization` | POST | Device Authorization Grant endpoint (RFC 8628). |
| `/token` | POST | Token endpoint for authorization code + PKCE, device code, and refresh token grants. |
| `/register` | POST | RFC 7591-style dynamic client registration. |
| `/setup` | GET/POST | First-run setup wizard endpoint, available only in setup mode. |
| `/health` | GET | Health check in normal mode. |
| `/<prefix>` | ANY | Reverse proxy to the matched upstream. Bearer-validated unless `auth=none` is set. |

## OAuth 監査ログ

認証開始、callback、token exchange、identity resolution、refresh、provider
token rotation の成功・失敗を、標準出力と専用 JSON Lines ファイルの両方へ
記録する。ファイルは1行1イベントで、`jq`、PowerShell、AI エージェントから
そのまま解析できる。

### 既定 path

| 実行環境 | 既定 path |
|----------|-----------|
| Windows | `%LOCALAPPDATA%\mcp-gateway\logs\auth-audit.jsonl` |
| Linux | `$XDG_STATE_HOME/mcp-gateway/logs/auth-audit.jsonl`。`XDG_STATE_HOME` 未設定時は `$HOME/.local/state/mcp-gateway/logs/auth-audit.jsonl` |
| macOS | `$HOME/Library/Logs/mcp-gateway/auth-audit.jsonl` |
| 公式 container image | `/data/mcp-gateway/logs/auth-audit.jsonl` |

公式 image は Linux 標準の `XDG_STATE_HOME=/data` を設定済みである。
compose を使わない `docker run` でも起動でき、`/data` に volume を mount
すると container 再作成後も保持できる。

```bash
docker run --rm -p 8080:8080 \
  --volume mcp-gateway-data:/data \
  --env OAUTH_CLIENT_ID=<client-id> \
  --env OAUTH_CLIENT_SECRET=<client-secret> \
  --env MCP_GATEWAY_BIND_ADDR=0.0.0.0:8080 \
  --env 'ROUTE_EXAMPLE=/mcp/example|http://example-mcp:8081' \
  ghcr.io/scottlz0310/mcp-gateway:latest
```

ネイティブ実行ではリポジトリを汚さないよう、相対 path、current working
directory への fallback、Git worktree 配下の明示 path を拒否する。OS の
ユーザー領域を解決できない場合や、保存先を作成・追記できない場合は起動失敗と
なる。

### ローテーション

- 現行ファイルが `MCP_GATEWAY_AUTH_AUDIT_MAX_SIZE_MB` に達すると UTC timestamp
  付きファイルへローテーションする。
- `MCP_GATEWAY_AUTH_AUDIT_MAX_BACKUPS` を超えた世代と、
  `MCP_GATEWAY_AUTH_AUDIT_MAX_AGE_DAYS` を超えたファイルを削除する。
- ローテーション済みファイルは AI 解析時に直接読めるよう圧縮しない。
- ファイルは owner のみ読み書き可能な permission で作成する。

監査イベントには token、authorization code、device code、OAuth `state`、
client secret、Authorization header、provider response body を保存しない。
相関が必要な token は短い SHA-256 fingerprint のみを記録する。

## GitHub OAuth Refresh Token Rotation

When the GitHub App is configured with **Expire user authorization tokens**
enabled, GitHub returns a `refresh_token` and an `expires_in` value alongside
each access token (typically 8 hours of access-token lifetime and 6 months of
refresh-token lifetime). The gateway can transparently rotate these tokens
before they expire, so a long-running upstream operation does not see the
access token become invalid mid-request.

GitHub Apps issue tokens with `ghu_` prefix (user-to-server access tokens) and
`ghr_` prefix (refresh tokens). The gateway handles both prefixes identically to
classic `gho_` OAuth App tokens — no additional configuration is required.

### Enabling Token Expiration on the GitHub App

To enable expiring tokens on your GitHub App:

1. Open **GitHub -> Settings -> Developer settings -> GitHub Apps -> Your App -> General**.
2. Scroll to **"User authorization tokens"** and check **"Expire user authorization tokens"**.
3. Save changes.

After this, every OAuth exchange will return `expires_in` (8 hours) and
`refresh_token` (`ghr_…`, valid for ~6 months) alongside the `ghu_` access token.

### Enabling Rotation in the Gateway

Set one of:

```bash
MCP_GATEWAY_GITHUB_REFRESH_ENABLED=true
```

or in `config.yaml`:

```yaml
gateway:
  github_refresh_enabled: true
```

Defaults to `false`. The flag is safe to leave on even when token expiration is
disabled on the GitHub App: the rotation path only fires when the cached token
entry has a non-zero `expires_in` hint and a refresh token, which non-expiring
configurations do not provide.

### Behavior

When the flag is on, every `ValidateToken` call inspects the cached provider
metadata for the bearer token:

1. If the provider access expiry is more than ~5 minutes away, rotation is
   skipped and the cached subject is returned as usual.
2. If the access expiry is within the leeway window, the gateway calls the
   GitHub token endpoint with `grant_type=refresh_token`.
3. On success, the new access token is cached under its own key and the
   rotated token is forwarded to the upstream MCP server via the request
   context. The original token's cache entry is **kept** (MCP clients
   continue presenting the original bearer), and its provider refresh
   metadata is updated to the freshly issued refresh token / expiry so the
   next in-window request from the same client triggers another rotation.
4. On any provider failure the gateway logs `rotation_failed`, leaves the
   cache as-is, and continues with the original token. If the upstream
   subsequently returns 401, the existing cache-invalidation path handles
   re-authentication.

The rotation is bound to whichever request happens to trigger it; in-flight
upstream operations on the old token are not interrupted. The
`review-raven` watch goroutines (issue #70) still see only the token they
captured at watch start — Phase A makes follow-on requests use the rotated
token, but does not retroactively patch background workers.

### Limitations

- A gateway restart loses the refresh token if `MCP_GATEWAY_TOKEN_STORE_PATH`
  is unset. Persist token state to disk to keep rotation working across
  restarts.
- The rotation lead time is fixed at ~5 minutes. Operators with significantly
  longer upstream operations should consider Phase B (delegated background
  access) instead of widening the leeway.
- Rotation requires `gateway.github_client_secret` because GitHub's refresh
  endpoint authenticates the rotation request the same way as the initial
  exchange.

### Troubleshooting

| Symptom | Likely cause |
|---------|--------------|
| Log entry `rotation_failed err=bad_refresh_token` | The GitHub App revoked the refresh token (manually or because the user reset it). Clients must re-authenticate. |
| Rotation never fires for any token | The GitHub App does not have "Expire user authorization tokens" enabled, or `expires_in` is missing from the token response. Verify the app setting in GitHub Developer Settings. |
| Rotation fires but the upstream still sees 401 | The upstream cached the old bearer in its own state (e.g. a `review-raven` watch goroutine). Phase A intentionally does not patch upstream state — this is the Phase B scope. |

## OAuth Resource Parameters

The gateway supports RFC 8707 `resource` parameters on:

- `/authorize`
- `/device_authorization`
- `/token` with `grant_type=refresh_token`

The resource must match a registered gateway or route audience. During the
migration grace period, legacy tokens without recorded audience metadata are
accepted while `MCP_GATEWAY_TOKEN_AUDIENCE_STRICT=false`.
