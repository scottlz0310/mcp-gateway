# copilot-review-routing example

This example shows how to route both `github-mcp-server` and `copilot-review-mcp` through a **single `mcp-gateway`** instance.

## Architecture

```
MCP Client
    │  url: http://127.0.0.1:8080/mcp/github          (github-mcp-server)
    │  url: http://127.0.0.1:8080/mcp/copilot-review  (copilot-review-mcp)
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
  - **Homepage URL**: `http://127.0.0.1:8080`
  - **Authorization callback URL**: `http://127.0.0.1:8080/callback`
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

## Notes

### Gateway mode (AUTH_MODE=gateway)

`copilot-review-mcp` runs in `AUTH_MODE=gateway` by default. In this mode it trusts the
`X-Authenticated-User` header injected by mcp-gateway and skips its own GitHub API call,
so there is only one token validation per request (in mcp-gateway).

To run `copilot-review-mcp` in standalone mode (direct access without mcp-gateway), set
`COPILOT_REVIEW_AUTH_MODE=standalone` in `.env`. Standalone mode requires its own OAuth App
credentials (`GITHUB_CLIENT_ID` / `GITHUB_CLIENT_SECRET` for copilot-review-mcp) in addition
to the mcp-gateway credentials. See `.env.example` for details.

### Shared OAuth App credentials

`OAUTH_CLIENT_ID`/`OAUTH_CLIENT_SECRET` (mcp-gateway; legacy
`GITHUB_MCP_CLIENT_ID`/`GITHUB_MCP_CLIENT_SECRET` still accepted) and
`GITHUB_CLIENT_ID`/`GITHUB_CLIENT_SECRET` (copilot-review-mcp, standalone mode only)
can point to the **same** GitHub OAuth App.
