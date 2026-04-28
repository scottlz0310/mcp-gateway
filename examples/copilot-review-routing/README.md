# copilot-review-routing example

This example shows how to route both `github-mcp-server` and `copilot-review-mcp` through a **single `mcp-gateway`** instance.

## Architecture

```
MCP Client
    │  url: http://localhost:8080/mcp/github          (github-mcp-server)
    │  url: http://localhost:8080/mcp/copilot-review  (copilot-review-mcp)
    ▼
mcp-gateway :8080  ← single OAuth façade + routing
    ├── /mcp/github          → http://github-mcp:8082          (Docker-internal)
    └── /mcp/copilot-review  → http://copilot-review-mcp:8083  (Docker-internal)
```

`copilot-review-mcp` registers a `/mcp/` subtree handler in Go's `ServeMux`, so the path
`/mcp/copilot-review` forwarded by mcp-gateway is handled correctly **without any code
changes** to copilot-review-mcp.

## Prerequisites

- Docker & Docker Compose v2
- A GitHub OAuth App (create at https://github.com/settings/applications/new)
  - **Homepage URL**: `http://localhost:8080`
  - **Authorization callback URL**: `http://localhost:8080/callback`
- A GitHub Personal Access Token (for `github-mcp-server`)

## Quick Start

```bash
# 1. Copy and fill in credentials
cp .env.example .env
$EDITOR .env

# 2. Start the stack
docker compose up -d

# 3. Verify health
curl http://localhost:8080/health
```

## MCP Client Configuration

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

## Notes

### Token double-validation

Currently, `mcp-gateway` **and** `copilot-review-mcp` each validate the Bearer token
against the GitHub API independently. Both services have an in-memory cache, so repeated
requests hit the cache after the first validation.

A future `AUTH_MODE=gateway` option for `copilot-review-mcp`
([copilot-review-mcp#12](https://github.com/scottlz0310/copilot-review-mcp/issues/12))
will trust the `X-Authenticated-User` header from mcp-gateway and skip the second
GitHub API call.

### Backward compatibility

Direct access to `copilot-review-mcp` (`http://localhost:8083`) continues to work — simply
uncomment the `ports` section in `docker-compose.yml`. No code changes required.

### Shared OAuth App credentials

`GITHUB_MCP_CLIENT_ID`/`GITHUB_MCP_CLIENT_SECRET` (mcp-gateway) and
`GITHUB_CLIENT_ID`/`GITHUB_CLIENT_SECRET` (copilot-review-mcp) can point to the **same**
GitHub OAuth App.
