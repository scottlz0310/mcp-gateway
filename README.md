# mcp-gateway

Unified authentication and routing gateway for MCP (Model Context Protocol) services — GitHub OAuth 2.0, multi-upstream reverse proxy, and Fly.io deployment ready.

> **Part of the [mcp-docker](https://github.com/scottlz0310/Mcp-Docker) ecosystem** — designed to work alongside `mcp-docker` and `copilot-review-mcp` as a composable self-hosted MCP infrastructure stack.

## Overview

`mcp-gateway` is a reverse proxy that centralizes **GitHub OAuth 2.0 authentication** and **request routing** for multiple MCP services. It acts as the single entry point for MCP clients (e.g., Claude Desktop, VS Code GitHub Copilot), handling the full OAuth 2.0 authorization code flow with PKCE before forwarding authenticated requests to upstream MCP servers.

It is the successor to `github-oauth-proxy` ([Mcp-Docker#102](https://github.com/scottlz0310/Mcp-Docker/issues/102)).

## Architecture

```
MCP Client (Claude Desktop / VS Code / etc.)
        │
        ▼
mcp-gateway  :8080
  ├── OAuth façade     /authorize  /callback  /token  /register
  ├── Bearer validation  (GitHub API with in-memory cache)
  └── Routing (longest-prefix match)
        ├── /mcp/github           → github-mcp-server  :8082
        └── /mcp/copilot-review   → copilot-review-mcp :8083
```

### 3-Repo Stack

| Repo | Role |
|------|------|
| **mcp-gateway** (this repo) | OAuth 2.0 auth + routing gateway |
| [mcp-docker](https://github.com/scottlz0310/Mcp-Docker) | Docker Compose orchestration for the full MCP stack |
| [copilot-review-mcp](https://github.com/scottlz0310/copilot-review-mcp) | Copilot code-review MCP server |

## Configuration

### Required Environment Variables

| Variable | Description |
|----------|-------------|
| `GITHUB_MCP_CLIENT_ID` | GitHub OAuth App Client ID |
| `GITHUB_MCP_CLIENT_SECRET` | GitHub OAuth App Client Secret |

At least one route must also be configured via `ROUTE_<NAME>` (see below) — the server exits on startup if no routes are defined.

### Route Configuration

Routes are defined via `ROUTE_<NAME>=<prefix>|<upstream_url>` environment variables.

```bash
ROUTE_GITHUB=/mcp/github|http://github-mcp:8082
ROUTE_COPILOT_REVIEW=/mcp/copilot-review|http://copilot-review-mcp:8083
```

- Prefixes **must** start with `/`
- Upstream URLs must be absolute `http` or `https`
- When multiple routes match, the **longest prefix wins**
- Append `|auth=none` as a third segment to disable Bearer validation for a specific route (e.g., for public or pre-auth endpoints):

  ```bash
  ROUTE_PUBLIC=/public|http://public-svc:8083|auth=none
  ```

### Optional Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `MCP_GATEWAY_BASE_URL` | `http://localhost:8080` | Base URL used for OAuth callback and discovery metadata |
| `MCP_GATEWAY_PORT` | `8080` | Listen port |
| `MCP_GATEWAY_TOKEN_STORE_PATH` | *(empty)* | Path to the persistent token store file (see [Persistent Auth State](#persistent-auth-state)) |
| `GITHUB_MCP_OAUTH_SCOPES` | `repo,user` | GitHub OAuth scopes |
| `LOG_LEVEL` | `info` | Log level: `debug` / `info` / `warn` / `error` |
| `SESSION_TTL_MIN` | `10` | OAuth session lifetime (minutes) |
| `TOKEN_CACHE_TTL_MIN` | `30` | Token validation cache TTL in minutes — used only when `MCP_GATEWAY_TOKEN_STORE_PATH` is **not** set |
| `TOKEN_EXPIRES_IN_SEC` | `7776000` | Token lifetime advertised to clients (seconds; default 90 days). Also used as the TTL for persistent token entries |
| `GITHUB_MCP_UPSTREAM_URL` | — | **Deprecated** — single upstream fallback when no `ROUTE_*` is set |

### Persistent Auth State

By default, validated token state is held only in process memory. This means that every time the gateway restarts, MCP clients (VS Code, Claude Desktop, etc.) must go through the browser OAuth flow again.

To avoid this, set `MCP_GATEWAY_TOKEN_STORE_PATH` to a writable file path:

```bash
MCP_GATEWAY_TOKEN_STORE_PATH=/data/tokens.json
```

The gateway will:
- Load previously validated token ↔ identity mappings on startup
- Save new mappings on each successful authentication
- Automatically sweep expired entries every minute
- Write the file with mode `0600` (owner read/write only)
- Store only SHA-256-hashed token keys — raw token values never appear on disk

> **Docker users:** mount a named volume at the store path so data survives container replacement.
> See the companion issue in [mcp-docker](https://github.com/scottlz0310/Mcp-Docker) for the recommended `docker-compose.yml` snippet.

To reset all authentication state (force re-auth for all clients), delete the store file and restart the gateway.

## Endpoints

| Path | Method | Description |
|------|--------|-------------|
| `/.well-known/oauth-authorization-server` | GET | RFC 8414 authorization server metadata |
| `/authorize` | GET | OAuth 2.0 authorization endpoint |
| `/callback` | GET | GitHub OAuth callback |
| `/device_authorization` | POST | Device Authorization Grant endpoint (RFC 8628) |
| `/token` | POST | Token endpoint — supports `authorization_code` + PKCE, `urn:ietf:params:oauth:grant-type:device_code`, and `refresh_token` grants |
| `/register` | POST | RFC 7591 dynamic client registration (pseudo) |
| `/health` | GET | Health check — returns `{"status":"ok"}` |
| `/<prefix>` | ANY | Bearer-validated reverse proxy to the matched upstream |

## Internal Design

### Provider Interface

The OAuth provider is abstracted behind a `Provider` interface, making it straightforward to add new identity providers (fly.io, OIDC, etc.) without touching the auth handler or middleware:

```go
type Provider interface {
    Name() string
    ClientID() string
    AuthorizeURL(state, codeChallenge string) string
    ExchangeCode(ctx context.Context, code string) (token string, scopes []string, err error)
    ValidateToken(ctx context.Context, token string) (Identity, error)
}

type Identity struct {
    Provider    string
    Subject     string // stable user identifier forwarded upstream
    DisplayName string // optional human-readable name for logging
}
```

The proxy forwards two headers to upstream MCP servers:

| Header | Value |
|--------|-------|
| `X-Authenticated-User` | `Identity.Subject` (canonical, provider-agnostic) |
| `X-GitHub-Login` | same as `X-Authenticated-User` (legacy compatibility; both set from `Identity.Subject`) |

Spoofable incoming headers (`X-Authenticated-User`, `X-GitHub-Login`) are stripped before proxying.

## Quick Start

### 1. Create a GitHub OAuth App

Go to **GitHub → Settings → Developer settings → OAuth Apps → New OAuth App**:

- **Authorization callback URL**: `http://localhost:8080/callback` (or your `MCP_GATEWAY_BASE_URL` + `/callback`)

### 2. Run with Docker Compose

```yaml
services:
  mcp-gateway:
    image: ghcr.io/scottlz0310/mcp-gateway:latest
    ports:
      - "8080:8080"
    environment:
      GITHUB_MCP_CLIENT_ID: <your-client-id>
      GITHUB_MCP_CLIENT_SECRET: <your-client-secret>
      MCP_GATEWAY_BASE_URL: http://localhost:8080
      ROUTE_GITHUB: /mcp/github|http://github-mcp:8082
    depends_on:
      - github-mcp
```

See [mcp-docker](https://github.com/scottlz0310/Mcp-Docker) for a full Compose stack.

### 2a. Multi-Upstream: github-mcp + copilot-review-mcp

Route multiple MCP services through a single gateway by adding more `ROUTE_*` entries.
A complete example that includes `copilot-review-mcp` is provided in
[`examples/copilot-review-routing/`](examples/copilot-review-routing/):

```yaml
services:
  mcp-gateway:
    image: ghcr.io/scottlz0310/mcp-gateway:latest
    ports:
      - "8080:8080"
    environment:
      GITHUB_MCP_CLIENT_ID: <your-client-id>
      GITHUB_MCP_CLIENT_SECRET: <your-client-secret>
      MCP_GATEWAY_BASE_URL: http://localhost:8080
      ROUTE_GITHUB: /mcp/github|http://github-mcp:8082
      ROUTE_COPILOT_REVIEW: /mcp/copilot-review|http://copilot-review-mcp:8083
    depends_on:
      - github-mcp
      - copilot-review-mcp
```

> **How it works**: `copilot-review-mcp` uses a Go `ServeMux` subtree handler (`/mcp/`),
> so the path `/mcp/copilot-review` forwarded by mcp-gateway is caught correctly without
> any code changes to `copilot-review-mcp`.

### 3. Configure your MCP Client

Add to your MCP client configuration (e.g., `claude_desktop_config.json`):

```json
{
  "mcpServers": {
    "github": {
      "url": "http://localhost:8080/mcp/github",
      "transport": "http"
    },
    "copilot-review": {
      "url": "http://localhost:8080/mcp/copilot-review",
      "transport": "http"
    }
  }
}
```

## Development

```bash
# Run tests
go test ./...

# Build binary
go build ./cmd/server

# Build Docker image
docker build -t mcp-gateway .
```

## Docker Image

```
ghcr.io/scottlz0310/mcp-gateway:latest
```

Built on `gcr.io/distroless/static-debian12:nonroot` — no shell, no package manager, runs as non-root (UID 65532).

## License

See [LICENSE](LICENSE).
