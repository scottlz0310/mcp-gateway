# Operations Guide

This guide covers day-to-day operation, health checks, log inspection, migration
notes, and common recovery procedures for mcp-gateway.

For the full configuration reference, see [configuration.md](configuration.md).

## Start And Stop

### Docker Compose

Use Docker Compose for the normal self-hosted stack.

```bash
docker compose up -d mcp-gateway
docker compose logs -f mcp-gateway
docker compose stop mcp-gateway
docker compose restart mcp-gateway
```

Docker port forwarding requires the gateway to listen on all interfaces inside
the container:

```yaml
services:
  mcp-gateway:
    image: ghcr.io/scottlz0310/mcp-gateway:latest
    ports:
      - "8080:8080"
    environment:
      OAUTH_CLIENT_ID: <your-client-id>
      OAUTH_CLIENT_SECRET: <your-client-secret>
      MCP_GATEWAY_BIND_ADDR: 0.0.0.0:8080
      MCP_GATEWAY_PUBLIC_URL: http://127.0.0.1:8080
      ROUTE_GITHUB: /mcp/github|http://github-mcp:8082
```

`MCP_GATEWAY_PUBLIC_URL` must be the URL that OAuth clients and the user's
browser can reach. It is often `http://127.0.0.1:8080` for local Docker
deployments even when `MCP_GATEWAY_BIND_ADDR` is `0.0.0.0:8080`.

### Bare Binary Or `go run`

When running outside Docker, the default token store path (`/data/tokens.json`)
usually does not exist. Point runtime files at writable local paths:

```bash
export MCP_GATEWAY_TOKEN_STORE_PATH=./tokens.json
export MCP_CONFIG_FILE=./config.yaml
export MCP_GATEWAY_KEY_PATH=./gateway.key
export OAUTH_CLIENT_ID=<your-client-id>
export OAUTH_CLIENT_SECRET=<your-client-secret>
export ROUTE_GITHUB=/mcp/github|http://127.0.0.1:8082

go run ./cmd/server
```

Build and run a local binary:

```bash
go build -o mcp-gateway ./cmd/server
./mcp-gateway
```

Stop the process with the supervisor that started it (`Ctrl-C`, `docker compose
stop`, `systemctl stop`, etc.). mcp-gateway does not require a special shutdown
endpoint.

## Health Checks

In normal mode:

```bash
curl -fsS http://127.0.0.1:8080/health
```

Expected response:

```json
{"status":"ok"}
```

If the gateway is in setup mode, `/health` returns `503 setup_required` because
only `/setup` is available until the required configuration is saved.
Use `curl -i http://127.0.0.1:8080/health` when checking setup mode; `curl -f`
exits non-zero for the expected 503 and may hide the response body.

For container health checks, use the same endpoint from the host or from another
container that can reach the published port:

```bash
curl -fsS http://mcp-gateway:8080/health
```

## Reading Logs

mcp-gateway writes JSON logs with Go `log/slog` to stdout. Set `LOG_LEVEL` to
`debug`, `info`, `warn`, or `error`; the default is `info`.

Each log entry includes the standard `slog` fields:

| Field | Meaning |
|-------|---------|
| `time` | Timestamp emitted by the JSON handler |
| `level` | `DEBUG`, `INFO`, `WARN`, or `ERROR` |
| `msg` | Event name |

### HTTP Access Logs

Every HTTP request emits one `"http request"` log after the handler returns.

| Field | Meaning |
|-------|---------|
| `method` | Request method |
| `path` | Request path without query string |
| `status` | Final HTTP status code |
| `latency_ms` | Request duration in milliseconds |
| `remote_addr` | Client address after trusted proxy processing |

5xx responses are logged at `ERROR`; other status ranges are logged at `INFO`.

Example:

```json
{"level":"INFO","msg":"http request","method":"GET","path":"/health","status":200,"latency_ms":0,"remote_addr":"127.0.0.1:53321"}
```

### Startup And Routing Logs

Startup emits `"registered route"` for each route and `"mcp-gateway starting"`
after the server is ready to listen.

| Message | Important fields |
|---------|------------------|
| `registered route` | `name`, `prefix`, `upstream`, `auth_required` |
| `mcp-gateway starting` | `bind_addr`, `public_url`, `provider`, `routes`, `trusted_proxies`, `token_audience_strict` |
| `setup wizard listening` | `bind_addr` |

### Proxy Logs

Authenticated upstream requests emit:

| Message | Important fields |
|---------|------------------|
| `proxy request` | `user`, `method`, `path`, `token_hash` |
| `proxy response` | `upstream_status`, `path` |
| `upstream rejected token; cache invalidated` | `path`, `token_hash` |

`token_hash` is the first 8 hex characters of `SHA-256(token)`. It is only for
correlation; raw token values are not logged.

### Auth And Setup Logs

Common authentication and setup messages:

| Message | Meaning |
|---------|---------|
| `auth failed` | Bearer token validation failed |
| `upstream error during auth` | Provider validation returned a transient upstream error |
| `token exchange rejected` | OAuth authorization-code exchange was invalid |
| `refresh token rejected` | Refresh token was missing, expired, or already consumed |
| `token without audience accepted during grace period` | Legacy token was accepted while `token_audience_strict` is disabled |
| `mcp-gateway starting in setup mode` | Required config is missing; follow `setup_url` |
| `setup complete; restarting to apply configuration` | Setup POST succeeded and the process is exiting with code 0 |

The setup-mode log includes `setup_url` and `token`. Treat the token as a
short-lived secret.

### Useful Log Commands

```bash
docker compose logs mcp-gateway | jq 'select(.msg=="http request")'
docker compose logs mcp-gateway | jq 'select(.level=="ERROR" or .level=="WARN")'
docker compose logs mcp-gateway | jq 'select(.msg=="proxy response" and .upstream_status>=500)'
```

If `jq` is not available, follow the raw logs:

```bash
docker compose logs -f mcp-gateway
```

### OAuth 監査ログファイル

OAuth 監査イベントは stdout に加え、ローテーション付き JSON Lines ファイルへ
保存される。既定 path は Windows では
`%LOCALAPPDATA%\mcp-gateway\logs\auth-audit.jsonl`、Linux では
`$XDG_STATE_HOME/mcp-gateway/logs/auth-audit.jsonl` または
`$HOME/.local/state/mcp-gateway/logs/auth-audit.jsonl`、macOS では
`$HOME/Library/Logs/mcp-gateway/auth-audit.jsonl` である。公式 container
image は `/data/mcp-gateway/logs/auth-audit.jsonl` を使用する。

PowerShell:

```powershell
$path = Join-Path $env:LOCALAPPDATA 'mcp-gateway\logs\auth-audit.jsonl'
Get-Content -LiteralPath $path |
  ForEach-Object { $_ | ConvertFrom-Json } |
  Where-Object result -eq 'failure' |
  Select-Object timestamp, phase, provider, error_class, oauth_error, http_status
```

Linux / macOS / container:

```bash
jq 'select(.result == "failure") |
  {timestamp, phase, provider, error_class, oauth_error, http_status}' \
  /data/mcp-gateway/logs/auth-audit.jsonl
```

直近の失敗は internal API が有効な場合に取得できる。endpoint は既存の
loopback + shared secret 境界を共有する。

```bash
curl -fsS \
  -H "Authorization: Bearer ${MCP_GATEWAY_INTERNAL_SECRET}" \
  "http://127.0.0.1:${MCP_GATEWAY_INTERNAL_PORT}/internal/v1/auth/failures?limit=20"
```

応答は最新順で最大100件である。永続的な事後解析の正本は JSON Lines
ファイルであり、internal API の履歴は process 再起動時に消失する。

## Common Problems

### `setup_required`

Symptoms:

- Non-`/setup` paths return `503 {"error":"setup_required","setup_url":"..."}`
- Logs contain `mcp-gateway starting in setup mode`

Cause:

- One or more required values are missing: GitHub client ID, GitHub client
  secret, or at least one route.

Fix:

1. Open the `setup_url` from logs, or run `GET /setup?token=<TOKEN>`.
2. POST the missing `client_id`, `client_secret`, and/or `routes`.
3. Let the supervisor restart the gateway after it exits with code 0.

### Setup Token Expired

Symptoms:

- `GET /setup?token=<TOKEN>` or `POST /setup?token=<TOKEN>` returns `408`.

Cause:

- Setup tokens are valid for 15 minutes.

Fix:

1. Restart the gateway while it is still missing required config.
2. Read the new `setup_url` and `token` from stdout.
3. Repeat the setup request.

### `gateway.key` Is Corrupt Or Unreadable

Symptoms:

- Startup exits before serving traffic.
- Logs contain `failed to load gateway encryption key`.

Cause:

- `gateway.key` exists but is empty, malformed, or unreadable. The gateway
  refuses to regenerate it automatically because doing so could permanently
  orphan encrypted secrets in `config.yaml`.

Fix:

1. Restore `gateway.key` from backup.
2. If the key was originally derived from `MCP_GATEWAY_MASTER_KEY`, remove the
   bad key file and restart with the same master key so the same identity is
   regenerated.
3. If no backup or master key exists, remove or replace the encrypted
   `auth.github_client_secret` in `config.yaml`, provide
   `OAUTH_CLIENT_SECRET` again (legacy `GITHUB_MCP_CLIENT_SECRET` also accepted
   with a deprecation warning), and let the gateway write a new encrypted
   value with a new key.

Do not delete `gateway.key` as a first response unless you know how the current
encrypted `config.yaml` can be recovered.

### `github_client_secret is unavailable`

Symptoms:

- Startup logs `github_client_secret is unavailable`.

Cause:

- Neither `auth.github_client_secret` in `config.yaml` nor
  `OAUTH_CLIENT_SECRET` (or legacy `GITHUB_MCP_CLIENT_SECRET`) is available.

Fix:

- Provide `OAUTH_CLIENT_SECRET` once so the gateway can encrypt and persist
  it, or restore a valid encrypted `auth.github_client_secret` and matching
  `gateway.key`. The deprecated `GITHUB_MCP_CLIENT_SECRET` is still accepted
  for backward compatibility but emits a startup warning.

### No Routes Configured

Symptoms:

- Startup logs `no routes configured: set ROUTE_<NAME>=<prefix>|<upstream_url>`.

Fix:

- Set at least one `ROUTE_<NAME>` environment variable, or add a `routes:` entry
  to `config.yaml`.

Example:

```bash
ROUTE_GITHUB=/mcp/github|http://github-mcp:8082
```

### Docker Port Is Published But The Gateway Is Unreachable

Symptoms:

- `docker compose ps` shows a published port, but host requests fail.

Cause:

- The gateway is bound to the loopback default (`127.0.0.1:8080`) inside the
  container.

Fix:

```bash
MCP_GATEWAY_BIND_ADDR=0.0.0.0:8080
```

Keep `MCP_GATEWAY_PUBLIC_URL` set to the browser-visible URL, for example
`http://127.0.0.1:8080`.

### GitHub OAuth Callback Mismatch

Symptoms:

- GitHub rejects the OAuth callback URL.
- Browser auth flow fails before returning to `/callback`.

Fix:

Update the GitHub OAuth App callback URL to exactly match:

```text
<MCP_GATEWAY_PUBLIC_URL>/callback
```

For the local default this is:

```text
http://127.0.0.1:8080/callback
```

### Bare Binary Fails Because `/data` Does Not Exist

Symptoms:

- Local `go run ./cmd/server` or a bare binary fails while opening the token
  store.

Fix:

```bash
export MCP_GATEWAY_TOKEN_STORE_PATH=./tokens.json
export MCP_CONFIG_FILE=./config.yaml
export MCP_GATEWAY_KEY_PATH=./gateway.key
```

### Invalid Trusted Proxy CIDR

Symptoms:

- Startup logs `invalid trusted proxy configuration`.

Fix:

- Ensure every `MCP_GATEWAY_TRUSTED_PROXIES` entry or
  `gateway.trusted_proxies` item is a valid CIDR such as `127.0.0.1/32` or
  `10.0.0.0/8`.

### Token Audience Mismatch

Symptoms:

- Authenticated route requests return 401 with `invalid_token`.
- Logs mention an audience mismatch or legacy audience grace-period acceptance.

Fix:

1. Make sure the client follows the `WWW-Authenticate.resource_metadata` URL.
2. Re-authenticate the client so it obtains a token for the route resource.
3. Keep `MCP_GATEWAY_TOKEN_AUDIENCE_STRICT=false` until legacy no-audience
   tokens have disappeared from logs.

## bind_addr vs public_url

mcp-gateway separates the listen address from the public URL:

| Config | Env var | YAML key | Default | Purpose |
|--------|---------|----------|---------|---------|
| Bind address | `MCP_GATEWAY_BIND_ADDR` | `gateway.bind_addr` | `127.0.0.1:8080` | Network interface and port the HTTP server listens on |
| Public URL | `MCP_GATEWAY_PUBLIC_URL` | `gateway.public_url` | `http://127.0.0.1:8080` | Canonical URL used in OAuth callbacks, discovery metadata, and PRM |

Before v0.3.0, `MCP_GATEWAY_BASE_URL` / `gateway.base_url` controlled only the
public URL. The server always listened on all interfaces (`:<port>`) regardless
of that setting. The old setting is deprecated and will be removed in a future
release.

### Why The Split Matters

In Docker deployments the gateway binds to `0.0.0.0:8080` so the host can reach
it via port forwarding, but the OAuth callback URL registered with GitHub must
be an address that the user's browser can reach. For local development that is
usually `http://127.0.0.1:8080`.

### Migrating From MCP_GATEWAY_BASE_URL

Update environment variables:

| Old | New |
|-----|-----|
| `MCP_GATEWAY_BASE_URL=http://localhost:<port>` | `MCP_GATEWAY_PUBLIC_URL=http://127.0.0.1:<port>` |
| implicit bind on all interfaces `:<port>` | `MCP_GATEWAY_BIND_ADDR=127.0.0.1:<port>` for local runs or `0.0.0.0:<port>` for Docker |

Update `config.yaml` if used:

```yaml
# Before
gateway:
  base_url: "http://localhost:<port>"

# After
gateway:
  public_url: "http://127.0.0.1:<port>"
  bind_addr: "127.0.0.1:<port>"
```

Update the GitHub OAuth App callback URL:

| Field | Old value | New value |
|-------|-----------|-----------|
| Authorization callback URL | `http://localhost:<port>/callback` | `http://127.0.0.1:<port>/callback` |

GitHub validates the exact callback URL, so the registered value must match the
URL sent by the gateway.

### Cutover Procedure

1. Deploy the updated gateway binary or image.
2. Update the GitHub OAuth App callback URL.
3. Update `docker-compose.yml`, a systemd unit, or `.env` with the new variables.
4. Restart the gateway.
5. Confirm `/health` returns `{"status":"ok"}`.

Existing access and refresh tokens remain valid unless the token store was
deleted or the provider has revoked the upstream token.

## Reverse Proxy Deployments

If TLS terminates in front of mcp-gateway, set the public URL to the external
origin and trust only the immediate proxy CIDRs:

```bash
MCP_GATEWAY_PUBLIC_URL=https://mcp.example.com
MCP_GATEWAY_BIND_ADDR=127.0.0.1:8080
MCP_GATEWAY_TRUSTED_PROXIES=127.0.0.1/32,10.0.0.0/8
```

Equivalent `config.yaml`:

```yaml
gateway:
  public_url: "https://mcp.example.com"
  bind_addr: "127.0.0.1:8080"
  trusted_proxies:
    - "127.0.0.1/32"
    - "10.0.0.0/8"
```

When the immediate peer IP matches `trusted_proxies`, mcp-gateway reflects:

| Header | Reflected request field |
|--------|-------------------------|
| `X-Forwarded-Proto` | `r.URL.Scheme`, only when the value is `http` or `https` |
| `X-Forwarded-Host` | `r.Host` after basic host validation |
| `X-Forwarded-For` | `r.RemoteAddr`, using the rightmost valid IP supplied by the trusted proxy |

When the peer is not trusted, `Forwarded`, `X-Forwarded-*`, and `X-Real-IP` are
stripped before later middleware and handlers run.

Configure the reverse proxy to overwrite or sanitize `X-Forwarded-For` instead
of passing client-provided values through unchanged. The gateway reads the
header from the right as a defense against appended spoofed entries, but the
proxy should still own this header.

Example nginx location:

```nginx
location / {
    proxy_set_header Host $host;
    proxy_set_header X-Forwarded-Host $host;
    proxy_set_header X-Forwarded-Proto $scheme;
    proxy_set_header X-Forwarded-For $remote_addr;
    proxy_pass http://127.0.0.1:8080;
}
```

`MCP_GATEWAY_PUBLIC_URL` remains the canonical OAuth, discovery, and PRM URL.
Keep it set to the same external origin that clients use.
