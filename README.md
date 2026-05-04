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

### GitHub OAuth Credentials

At startup, the gateway resolves the GitHub OAuth credentials as follows:

| Credential | Primary source | Fallback |
|-----------|----------------|---------|
| `GITHUB_MCP_CLIENT_ID` | `GITHUB_MCP_CLIENT_ID` env var | `auth.github_client_id` in `config.yaml` |
| `GITHUB_MCP_CLIENT_SECRET` | `auth.github_client_secret` in `config.yaml` (may be `ENC[age:]...`) | `GITHUB_MCP_CLIENT_SECRET` env var *(first-startup seeding only — ignored once a value exists in config.yaml)* |

At least one route must also be configured via `ROUTE_<NAME>` (see below) — the server exits on startup if no routes are defined.

### Secret Encryption

The gateway can store the GitHub OAuth client secret **encrypted at rest** in `config.yaml` using [age](https://age-encryption.org/) X25519 encryption.

#### How it works

On startup, the gateway:

1. Loads (or generates) an X25519 key from `gateway.key` (path: `MCP_GATEWAY_KEY_PATH`, default `./gateway.key`)
2. Reads `config.yaml` (`MCP_CONFIG_FILE`, default `./config.yaml`) if it exists
3. Resolves `github_client_secret` using this priority:
   - `ENC[age:]...` in `config.yaml` → decrypts and uses the plaintext
   - Plaintext in `config.yaml` → encrypts it, rewrites the file, uses the plaintext
   - No secret in config + `GITHUB_MCP_CLIENT_SECRET` env var → encrypts it, writes to config, uses the plaintext
   - Neither → startup fails with a clear error message

Secrets are **never logged** — neither the plaintext value, nor the `ENC[...]` ciphertext, nor the key contents.

#### Key file (`gateway.key`)

The key file stores a standard `age-keygen`-compatible X25519 identity string (`AGE-SECRET-KEY-1...`).

**Generation priority:**

| Condition | Result |
|-----------|--------|
| `gateway.key` exists | Load and use as-is; `MCP_GATEWAY_MASTER_KEY` is **ignored** |
| `gateway.key` absent + `MCP_GATEWAY_MASTER_KEY` set | Deterministically derive X25519 key via HKDF-SHA256; save to file |
| `gateway.key` absent + no master key | Generate a random X25519 key; save to file |

> **⚠ Corruption is fatal.** If `gateway.key` exists but is empty, unreadable, or malformed, the gateway will **not** regenerate it — it will exit immediately. This protects against accidental data loss (overwriting the key would permanently destroy any encrypted secrets in `config.yaml`). To recover, restore `gateway.key` from backup or re-encrypt `config.yaml` with a known key.

The file is written with `0600` permissions. On Windows volumes where `chmod` is not supported, a warning is logged.

**Back up `gateway.key` securely.** If the key file is lost and `MCP_GATEWAY_MASTER_KEY` was not used (random generation), the encrypted secrets in `config.yaml` cannot be recovered.

#### `MCP_GATEWAY_MASTER_KEY`

When set, the master key is used to deterministically derive the X25519 key (HKDF-SHA256). This enables secret encryption without a separate key file backup — the same master key always produces the same `gateway.key`.

**Requirements:**
- Minimum **32 bytes** — shorter values are rejected at startup
- Use a sufficiently random value (e.g. output of `openssl rand -hex 32`)
- **Leaked master key = leaked derived key = encrypted secrets can be decrypted** — treat it as a secret

> Once `gateway.key` exists, `MCP_GATEWAY_MASTER_KEY` is ignored. It is only used when generating the key file for the first time.

`MCP_MASTER_KEY` is accepted as a legacy alias for `MCP_GATEWAY_MASTER_KEY`.

#### Example `config.yaml`

```yaml
auth:
  github_client_id: "Ov23liXXXX"
  github_client_secret: "ENC[age:]<base64-ciphertext>"
gateway:
  base_url: "http://localhost:8080"
  port: "8080"
  oauth_scopes: "repo,user"
```

All `gateway:` fields are optional — values fall back to the corresponding env vars and then to the built-in defaults.

#### Docker Compose setup

```yaml
services:
  mcp-gateway:
    volumes:
      - ./data:/data
    environment:
      MCP_GATEWAY_KEY_PATH: /data/gateway.key
      MCP_CONFIG_FILE: /data/config.yaml
      # On first run only — omit once gateway.key exists:
      # MCP_GATEWAY_MASTER_KEY: "${MCP_GATEWAY_MASTER_KEY}"
      GITHUB_MCP_CLIENT_ID: "${GITHUB_MCP_CLIENT_ID}"
      # GITHUB_MCP_CLIENT_SECRET only needed on first run to seed config.yaml:
      # GITHUB_MCP_CLIENT_SECRET: "${GITHUB_MCP_CLIENT_SECRET}"
      # At least one ROUTE_* is required — the gateway will fail to start without routes:
      ROUTE_GITHUB: /mcp/github|http://github-mcp:8082
```


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
| `MCP_GATEWAY_KEY_PATH` | `./gateway.key` | Path to the X25519 encryption key file (see [Secret Encryption](#secret-encryption)) |
| `MCP_CONFIG_FILE` | `./config.yaml` | Path to `config.yaml` for persisted configuration |
| `MCP_GATEWAY_MASTER_KEY` | — | Master key for deterministic key derivation (≥32 bytes; see [Secret Encryption](#secret-encryption)) |
| `MCP_GATEWAY_BASE_URL` | `http://localhost:8080` | Base URL used for OAuth callback and discovery metadata |
| `MCP_GATEWAY_PORT` | `8080` | Listen port |
| `MCP_GATEWAY_TOKEN_STORE_PATH` | `/data/tokens.json` | Path to the persistent token store file (see [Persistent Auth State](#persistent-auth-state)) |
| `GITHUB_MCP_OAUTH_SCOPES` | `repo,user` | GitHub OAuth scopes |
| `LOG_LEVEL` | `info` | Log level: `debug` / `info` / `warn` / `error` |
| `SESSION_TTL_MIN` | `10` | OAuth session lifetime (minutes) |
| `TOKEN_CACHE_TTL_MIN` | `30` | Token validation cache TTL in minutes — used only when `MCP_GATEWAY_TOKEN_STORE_PATH` is explicitly set to empty |
| `TOKEN_EXPIRES_IN_SEC` | `7776000` | Token lifetime advertised to clients (seconds; default 90 days). Also used as the TTL for persistent token entries |
| `GITHUB_MCP_UPSTREAM_URL` | — | **Deprecated** — single upstream fallback when no `ROUTE_*` is set |

### Persistent Auth State

> **Docker default:** The default store path `/data/tokens.json` is designed for Docker deployments — the Docker image pre-creates `/data` with the correct permissions. If you run the gateway with `go run` or a bare binary outside Docker, `/data` likely does not exist and the gateway will fail to start. In that case set `MCP_GATEWAY_TOKEN_STORE_PATH` to a writable path (e.g. `./tokens.json`) or set it to empty to disable persistence.

By default, validated token state is persisted to `/data/tokens.json`. This means MCP clients (VS Code, Claude Desktop, etc.) **do not need to re-authenticate after gateway restarts** under normal operation.

To change the store path, set `MCP_GATEWAY_TOKEN_STORE_PATH`. To disable persistence and revert to in-memory-only storage (not recommended for production), set it to an empty string:

```bash
MCP_GATEWAY_TOKEN_STORE_PATH=/data/tokens.json  # default (Docker)
MCP_GATEWAY_TOKEN_STORE_PATH=./tokens.json       # local run
MCP_GATEWAY_TOKEN_STORE_PATH=                   # disable persistence (not recommended)
```

The gateway will:
- Load previously validated token ↔ identity mappings on startup
- Save new mappings on each successful authentication
- Automatically sweep expired entries every minute
- Write the file with mode `0600` (owner read/write only)
- Store only SHA-256-hashed token keys — raw token values never appear on disk

Setting `MCP_GATEWAY_TOKEN_STORE_PATH` also enables refresh token persistence: on the first refresh token issuance (which can occur during the initial `authorization_code` or device grant, not only on a subsequent `refresh_token` grant), a sibling file at `<path>.refresh` (e.g. `/data/tokens.json.refresh`) is created (the file may not exist immediately after startup until the first refresh token is issued). This ensures that gateway-issued refresh tokens survive container restarts, so clients can transparently continue their session via the `refresh_token` grant without triggering a full browser re-authentication.

> **Security note:** The `.refresh` file stores the **associated access token value in plaintext** alongside a hashed refresh token key. The gateway must re-present the access token to the upstream provider on refresh, so the plaintext value is required. The file is written with mode `0600` (owner read/write only) and should be treated with the same sensitivity as the primary token store file — store both files on an encrypted volume or a `tmpfs` mount in high-security environments.

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
| `/<prefix>` | ANY | Reverse proxy to the matched upstream — Bearer-validated unless `auth=none` is set for the matched route |

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
