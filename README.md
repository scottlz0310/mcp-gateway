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

### 1. Create A GitHub OAuth App

Open **GitHub -> Settings -> Developer settings -> OAuth Apps -> New OAuth App**.

Use this callback URL for local development:

```text
http://127.0.0.1:8080/callback
```

For deployed environments, use `<MCP_GATEWAY_PUBLIC_URL>/callback`.

### 2. Run With Docker Compose

```yaml
services:
  mcp-gateway:
    image: ghcr.io/scottlz0310/mcp-gateway:latest
    ports:
      - "8080:8080"
    environment:
      GITHUB_MCP_CLIENT_ID: <your-client-id>
      GITHUB_MCP_CLIENT_SECRET: <your-client-secret>
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
| [mcp-docker](https://github.com/scottlz0310/Mcp-Docker) | Docker Compose orchestration for the full MCP stack. |
| [copilot-review-mcp](https://github.com/scottlz0310/copilot-review-mcp) | Copilot code-review MCP server. |

## Documentation

| Document | Purpose |
|----------|---------|
| [docs/README.md](docs/README.md) | Documentation index. |
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

## Core Configuration

Minimal Docker environment:

```yaml
environment:
  GITHUB_MCP_CLIENT_ID: <your-client-id>
  GITHUB_MCP_CLIENT_SECRET: <your-client-secret>
  MCP_GATEWAY_BIND_ADDR: 0.0.0.0:8080
  MCP_GATEWAY_PUBLIC_URL: http://127.0.0.1:8080
  ROUTE_GITHUB: /mcp/github|http://github-mcp:8082
```

Important paths:

| Setting | Default | Notes |
|---------|---------|-------|
| `MCP_CONFIG_FILE` | `./config.yaml` | Persisted setup and encrypted secrets. |
| `MCP_GATEWAY_KEY_PATH` | `./gateway.key` | age X25519 identity. Back it up securely. |
| `MCP_GATEWAY_TOKEN_STORE_PATH` | `/data/tokens.json` | Docker-friendly token persistence path. Use a writable local path outside Docker. |

The full reference is in [docs/configuration.md](docs/configuration.md).

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
