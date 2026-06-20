# mcp-gateway

Unified authentication and routing gateway for MCP (Model Context Protocol)
services.

mcp-gateway centralizes GitHub OAuth 2.0 authentication, MCP Authorization
metadata, and reverse proxy routing for multiple upstream MCP servers. It is the
single HTTP entry point for MCP clients such as Claude Desktop and VS Code.

> Part of the [mcp-docker](https://github.com/scottlz0310/Mcp-Docker)
> ecosystem, designed to run alongside `mcp-docker` and
> `copilot-review-mcp`.

## Getting Started

### 1. Create A GitHub App

Open **GitHub -> Settings -> Developer settings -> GitHub Apps -> New GitHub App**.

Configure the following settings:

- **Callback URLs** — register both endpoints:
  ```text
  http://127.0.0.1:8080/callback
  http://127.0.0.1:8080/device_callback
  ```
  For deployed environments, replace `http://127.0.0.1:8080` with `<MCP_GATEWAY_PUBLIC_URL>`.
- **Permissions** — recommended settings:

  | Category | Permission | Access |
  |----------|-----------|--------|
  | Repository | Metadata | Read-only (auto-selected) |
  | Repository | Contents | Read-only |
  | Repository | Issues | Read and write |
  | Repository | Pull requests | Read and write |
  | Account | Email addresses | Read-only |

  `Email addresses` is required for user identification. The repository permissions
  are needed by `review-raven` / `github-mcp-server` upstreams. Adjust to the
  minimum required by your own MCP upstreams.
- **Webhook** — leave disabled (not used by the OAuth flow).
- **Where can this GitHub App be installed?** — `Only on this account` for personal use.

After creation, generate a **Client secret** from the app settings page and copy the **Client ID**.

> **Migrating from a GitHub OAuth App?** Replace `OAUTH_CLIENT_ID` and
> `OAUTH_CLIENT_SECRET` with the new GitHub App credentials. No code or
> config changes are needed — the gateway works with both `gho_` (OAuth App)
> and `ghu_` (GitHub App) user access tokens.
>
> **Expiring tokens:** To enable short-lived `ghu_` tokens with automatic
> rotation, check "Expire user authorization tokens" in the GitHub App settings
> and set `MCP_GATEWAY_GITHUB_REFRESH_ENABLED=true` in the gateway.
> See [docs/configuration.md](docs/configuration.md#github-oauth-refresh-token-rotation) for details.

### 2. Run With Docker Compose

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
    depends_on:
      - github-mcp
```

See [mcp-docker](https://github.com/scottlz0310/Mcp-Docker) for a full Compose
stack.

### 3. Configure An MCP Client

Example MCP client configuration:

```json
{
  "mcpServers": {
    "github": {
      "url": "http://127.0.0.1:8080/mcp/github",
      "transport": "http"
    }
  }
}
```

For multiple upstreams, add more `ROUTE_*` entries and point each client server
at its route:

```yaml
environment:
  ROUTE_GITHUB: /mcp/github|http://github-mcp:8082
  ROUTE_COPILOT_REVIEW: /mcp/copilot-review|http://copilot-review-mcp:8083
```

```json
{
  "mcpServers": {
    "github": {
      "url": "http://127.0.0.1:8080/mcp/github",
      "transport": "http"
    },
    "copilot-review": {
      "url": "http://127.0.0.1:8080/mcp/copilot-review",
      "transport": "http"
    }
  }
}
```

A complete multi-upstream example is available in
[`examples/copilot-review-routing/`](examples/copilot-review-routing/).

### 4. Check Health

```bash
curl -fsS http://127.0.0.1:8080/health
```

Expected response:

```json
{"status":"ok"}
```

## How It Works

```text
MCP Client (Claude Desktop / VS Code / etc.)
        |
        v
mcp-gateway  :8080
  |-- OAuth facade       /authorize  /callback  /token  /register
  |-- MCP auth metadata  /.well-known/oauth-*
  |-- Bearer validation  GitHub API with local cache and persistence
  `-- Routing           longest-prefix match
        |-- /mcp/github          -> github-mcp-server  :8082
        `-- /mcp/copilot-review  -> copilot-review-mcp :8083
```

mcp-gateway is the successor to `github-oauth-proxy`
([Mcp-Docker#102](https://github.com/scottlz0310/Mcp-Docker/issues/102)).

### Repository Stack

| Repo | Role |
|------|------|
| **mcp-gateway** | OAuth 2.0 auth, MCP authorization metadata, token persistence, and routing gateway. |
| [thread-owl](https://github.com/scottlz0310/thread-owl) | Reviewer-side MCP server: webhook handling, review candidate judgment, and queue management. |
| [mcp-resource-subscriber](https://github.com/scottlz0310/mcp-resource-subscriber) | Subscription client and agent workflow bridge for MCP resource notifications. |
| [review-raven](https://github.com/scottlz0310/review-raven) | Reviewed-side MCP: fetch Copilot review threads, reply, resolve, and re-request review. |
| [mcp-docker](https://github.com/scottlz0310/Mcp-Docker) | Container orchestration, gateway config generation, and CLI agent config automation. |
| [squirrel-notifier](https://github.com/scottlz0310/squirrel-notifier) | Desktop-resident notification receiver and AI agent launcher: monitors MCP resource updates via mcp-gateway, shows toast notifications, and launches local AI agents with skill directives. |

## Documentation

| Document | Purpose |
|----------|---------|
| [docs/README.md](docs/README.md) | Documentation index. |
| [docs/architecture.md](docs/architecture.md) | Review platform overview, responsibility boundaries, and design principles. |
| [docs/configuration.md](docs/configuration.md) | Full environment variable, `config.yaml`, route, token store, reverse proxy, and endpoint reference. |
| [docs/operations.md](docs/operations.md) | Start/stop procedures, health checks, structured logs, troubleshooting, and migration notes. |
| [docs/runbook-e2e-v0.1.0.md](docs/runbook-e2e-v0.1.0.md) | End-to-end acceptance runbook. |

## First-Run Setup Wizard

If the GitHub client ID, GitHub client secret, or route configuration is missing,
the gateway enters setup mode instead of exiting.

What happens:

1. The gateway listens on the normal bind address.
2. A one-time setup token with a 15-minute TTL is printed to stdout.
3. All paths except `/setup` return `503 setup_required`.

Example setup flow:

```bash
curl "http://127.0.0.1:8080/setup?token=<TOKEN>"

curl -X POST "http://127.0.0.1:8080/setup?token=<TOKEN>" \
  -H "Content-Type: application/json" \
  -d '{
    "client_id": "Ov23liXXXXXXXXXX",
    "client_secret": "your-github-oauth-secret",
    "routes": [
      {"name": "github", "prefix": "/mcp/github", "upstream": "http://github-mcp:8082"}
    ]
  }'
```

On successful `POST`, the gateway writes `config.yaml`, encrypts the secret with
age, consumes the token, and exits with code 0 so the process supervisor can
restart it in normal mode.

Operational details and recovery procedures are in
[docs/operations.md](docs/operations.md).

## Key Features

- GitHub OAuth 2.0 authorization code + PKCE.
- Device Authorization Grant and refresh token grant.
- RFC 8414 authorization server metadata.
- RFC 9728 Protected Resource Metadata, including per-route PRM documents.
- RFC 8707 `resource` parameter support for audience-bound tokens.
- Dynamic client registration endpoint for MCP clients.
- Multi-upstream reverse proxy routing with longest-prefix matching.
- Route-level `auth=none` bypass for explicitly public upstreams.
- Persistent token and refresh-token state.
- age X25519 encryption for stored GitHub OAuth client secrets.
- Structured JSON logs with request, auth, setup, and proxy events.
- Trusted reverse proxy header handling for TLS-terminating proxies.
- **Upstream OAuth delegation**: per-route upstream OAuth with `authorization_code` (user-interactive) or `client_credentials` (service-to-service) grant, automatic AS discovery (RFC 9728 + RFC 8414), Dynamic Client Registration, per-user token persistence, proactive refresh, and transparent 401 retry.

## Core Configuration

Minimal Docker environment:

```yaml
environment:
  OAUTH_CLIENT_ID: <your-client-id>
  OAUTH_CLIENT_SECRET: <your-client-secret>
  MCP_GATEWAY_BIND_ADDR: 0.0.0.0:8080
  MCP_GATEWAY_PUBLIC_URL: http://127.0.0.1:8080
  ROUTE_GITHUB: /mcp/github|http://github-mcp:8082
```

Important paths:

| Setting | Default | Notes |
|---------|---------|-------|
| `MCP_CONFIG_FILE` | `{state-dir}/config.yaml` | Persisted setup and encrypted secrets. |
| `MCP_GATEWAY_KEY_PATH` | `{state-dir}/gateway.key` | age X25519 identity. Back it up securely. |
| `MCP_GATEWAY_TOKEN_STORE_PATH` | `{state-dir}/tokens.json` | Persistent token store. Docker deployments pin this via env var. |
| `MCP_GATEWAY_AUTH_AUDIT_LOG_PATH` | OS user state directory; `/data/mcp-gateway/logs/auth-audit.jsonl` in the official image | Rotating OAuth audit JSON Lines file. Relative paths and Git worktree paths are rejected. |
| *(auto)* | `{state-dir}/upstream_clients.json` | Upstream AS Dynamic Client Registration records (mode 0600). Created on first upstream OAuth route access. |
| *(auto)* | `{state-dir}/upstream_tokens.json` | Per-user upstream OAuth access/refresh tokens (mode 0600). Created on first upstream OAuth authorization. |

`{state-dir}` is the OS user state directory resolved at startup (Windows: `%LOCALAPPDATA%\mcp-gateway`, macOS: `~/Library/Application Support/mcp-gateway`, Linux: `$XDG_STATE_HOME/mcp-gateway` → `~/.local/state/mcp-gateway`). Docker deployments always override paths via environment variables. See [docs/configuration.md](docs/configuration.md) for the full reference.

## Endpoints

| Path | Method | Description |
|------|--------|-------------|
| `/.well-known/oauth-authorization-server` | GET | Authorization server metadata. |
| `/.well-known/oauth-protected-resource` | GET | Gateway-wide Protected Resource Metadata. |
| `/.well-known/oauth-protected-resource/<prefix>` | GET | Per-route Protected Resource Metadata, e.g. `/.well-known/oauth-protected-resource/mcp/github`. |
| `/authorize` | GET | OAuth authorization endpoint. |
| `/callback` | GET | GitHub OAuth callback. |
| `/device_authorization` | POST | Device Authorization Grant endpoint. |
| `/token` | POST | Authorization code, device code, and refresh token grants. |
| `/register` | POST | Dynamic client registration. |
| `/upstream/callback/{routeName}` | GET | Upstream OAuth authorization code callback (authorization_code flow only). |
| `/setup` | GET/POST | First-run setup wizard, available in setup mode. |
| `/health` | GET | Health check in normal mode. |
| `/<prefix>` | ANY | Reverse proxy to the matched upstream. |

## Internal Design

OAuth provider-specific behavior is behind a `Provider` interface:

```go
type Provider interface {
    Name() string
    ClientID() string
    Scopes() string
    AuthorizeURL(state, codeChallenge string) string
    ExchangeCode(ctx context.Context, code string) (token string, scopes []string, err error)
    ValidateToken(ctx context.Context, token string) (Identity, error)
}
```

The proxy forwards the authenticated identity to upstream MCP servers:

| Header | Value |
|--------|-------|
| `X-Authenticated-User` | Provider-agnostic authenticated subject. |
| `X-GitHub-Login` | Same value, retained for legacy upstream compatibility. |

Spoofable incoming identity and forwarded headers are stripped before proxying.

## Development

```bash
go test ./...
go build ./cmd/server
docker build -t mcp-gateway .
```

## Docker Image

```text
ghcr.io/scottlz0310/mcp-gateway:latest
```

The image is based on `gcr.io/distroless/static-debian12:nonroot` and runs as
UID 65532.

## License

See [LICENSE](LICENSE).
