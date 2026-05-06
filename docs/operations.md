# Operations Guide

This guide covers deployment, migration, and operational considerations for mcp-gateway.

---

## bind_addr vs public_url

mcp-gateway v0.3.0 separates the **listen address** from the **public URL**:

| Config | Env var | YAML key | Default | Purpose |
|--------|---------|----------|---------|---------|
| Bind address | `MCP_GATEWAY_BIND_ADDR` | `gateway.bind_addr` | `127.0.0.1:8080` | Network interface/port the HTTP server listens on |
| Public URL | `MCP_GATEWAY_PUBLIC_URL` | `gateway.public_url` | `http://127.0.0.1:8080` | Canonical URL used in OAuth callbacks, discovery metadata, and PRM |

Before v0.3.0, `MCP_GATEWAY_BASE_URL` / `gateway.base_url` controlled only the **public URL**
(OAuth callbacks and discovery metadata). The server always listened on all interfaces
(`:<port>`) regardless of this setting.
That setting is now **deprecated** and will be removed in a future release.

### Why the split matters

In Docker deployments the gateway binds to `0.0.0.0:8080` (all interfaces) so the host can
reach it via port-forwarding, but the OAuth callback URL registered with GitHub must be an
address that the **user's browser** can reach—typically `http://127.0.0.1:8080` on the
developer's machine.

Before v0.3.0 there was no clean way to express this difference: the server always
listened on all interfaces (`:<port>`), but `BASE_URL` only influenced the public URL
advertised to OAuth clients—there was no way to configure the bind address independently.

---

## Migrating from MCP_GATEWAY_BASE_URL

### 1. Update your environment variables

| Old | New |
|-----|-----|
| `MCP_GATEWAY_BASE_URL=http://localhost:8080` | `MCP_GATEWAY_PUBLIC_URL=http://127.0.0.1:8080` |
| *(implicit: bind on all interfaces `:8080`)* | `MCP_GATEWAY_BIND_ADDR=127.0.0.1:8080` (local) or `0.0.0.0:8080` (Docker) |

### 2. Update config.yaml (if used)

```yaml
# Before
gateway:
  base_url: "http://localhost:8080"

# After
gateway:
  public_url: "http://127.0.0.1:8080"
  bind_addr: "127.0.0.1:8080"   # omit for Docker; set to 0.0.0.0:8080 there
```

### 3. Update the GitHub OAuth App callback URL

Go to **GitHub → Settings → Developer settings → OAuth Apps → [your app] → Edit**:

| Field | Old value | New value |
|-------|-----------|-----------|
| Authorization callback URL | `http://localhost:8080/callback` | `http://127.0.0.1:8080/callback` |

> **Note:** `localhost` and `127.0.0.1` are treated the same by most browsers, but GitHub
> OAuth validates the exact callback URL, so the registered URL must match what the gateway
> sends in the OAuth redirect.

### 4. Cutover procedure

1. Merge or deploy the updated gateway binary / image.
2. Update the GitHub OAuth App callback URL (step 3 above).
3. Update your `docker-compose.yml` or systemd unit / `.env` file (steps 1–2 above).
4. Restart the gateway.
5. Existing tokens remain valid—clients do **not** need to re-authenticate unless the
   token store was cleared.

---

## Docker deployment

The gateway default bind address is `127.0.0.1:8080` (loopback only).
Docker port-forwarding requires binding on all interfaces:

```yaml
services:
  mcp-gateway:
    image: ghcr.io/scottlz0310/mcp-gateway:latest
    ports:
      - "8080:8080"
    environment:
      GITHUB_MCP_CLIENT_ID: <your-client-id>
      GITHUB_MCP_CLIENT_SECRET: <your-client-secret>
      # Bind on all interfaces so Docker port-forwarding works
      MCP_GATEWAY_BIND_ADDR: 0.0.0.0:8080
      # Public URL is what the user's browser (and GitHub OAuth) will call
      MCP_GATEWAY_PUBLIC_URL: http://127.0.0.1:8080
      ROUTE_GITHUB: /mcp/github|http://github-mcp:8082
    depends_on:
      - github-mcp
```

If you are deploying behind a reverse proxy (nginx, Caddy, etc.) and exposing the gateway
on a public domain, set `MCP_GATEWAY_PUBLIC_URL` to the full public URL, e.g.:

```
MCP_GATEWAY_PUBLIC_URL=https://mcp.example.com
MCP_GATEWAY_BIND_ADDR=127.0.0.1:8080
```

---

## Non-Docker / bare binary

When running the binary directly (not in Docker) the `/data` directory may not exist.
Override the storage paths to writable locations:

```bash
export MCP_GATEWAY_TOKEN_STORE_PATH=./tokens.json
export MCP_CONFIG_FILE=./config.yaml
export MCP_GATEWAY_KEY_PATH=./gateway.key
```

Or disable token persistence entirely (not recommended for production):

```bash
export MCP_GATEWAY_TOKEN_STORE_PATH=
```

---

## Token store persistence

See [README.md — Authentication state persistence](../README.md#authentication-state-persistence)
for full details on the token store, refresh token store, and how to reset auth state.
