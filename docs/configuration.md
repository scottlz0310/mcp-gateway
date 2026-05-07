# Configuration Reference

This page is the detailed configuration reference for mcp-gateway. The README
keeps only the quick-start path and links here for full operational settings.

## Required Startup Inputs

mcp-gateway needs all of the following before it can run in normal mode:

| Requirement | Environment source | `config.yaml` source |
|-------------|--------------------|----------------------|
| GitHub OAuth client ID | `GITHUB_MCP_CLIENT_ID` | `auth.github_client_id` |
| GitHub OAuth client secret | `GITHUB_MCP_CLIENT_SECRET` for first-start seeding | `auth.github_client_secret` |
| At least one route | `ROUTE_<NAME>` | `routes:` |

If any required value is missing, the gateway enters setup mode and prints a
one-time `/setup` URL to stdout.

## Precedence

Configuration is resolved in this order:

| Setting | Precedence |
|---------|------------|
| GitHub client ID | `GITHUB_MCP_CLIENT_ID` > `auth.github_client_id` |
| GitHub client secret | encrypted/plain `auth.github_client_secret` > non-empty `GITHUB_MCP_CLIENT_SECRET` used to seed `config.yaml` |
| Routes | `ROUTE_<NAME>` env vars > `routes:` in `config.yaml` > deprecated `GITHUB_MCP_UPSTREAM_URL` fallback |
| Public URL | `MCP_GATEWAY_PUBLIC_URL` > deprecated `MCP_GATEWAY_BASE_URL` > `gateway.public_url` > deprecated `gateway.base_url` > default |
| Bind address | `MCP_GATEWAY_BIND_ADDR` > `gateway.bind_addr` > `127.0.0.1:<resolved-port>` |
| OAuth scopes | `GITHUB_MCP_OAUTH_SCOPES` > `gateway.oauth_scopes` > `repo,user` |
| Trusted proxies | `MCP_GATEWAY_TRUSTED_PROXIES` > `gateway.trusted_proxies` > none |
| Token audience strict mode | `MCP_GATEWAY_TOKEN_AUDIENCE_STRICT` > `gateway.token_audience_strict` > `false` |

The GitHub client secret is intentionally special: once `config.yaml` contains a
secret, `GITHUB_MCP_CLIENT_SECRET` is ignored except during first-start seeding.

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `GITHUB_MCP_CLIENT_ID` | none | GitHub OAuth App client ID. Required unless `auth.github_client_id` is set. |
| `GITHUB_MCP_CLIENT_SECRET` | none | GitHub OAuth App client secret. Used to seed encrypted `config.yaml` when no config secret exists. |
| `GITHUB_MCP_OAUTH_SCOPES` | `repo,user` | GitHub OAuth scopes requested by the gateway. |
| `ROUTE_<NAME>` | none | Route definition in `<prefix>|<upstream_url>[|auth=none]` form. At least one route is required unless configured in `config.yaml`. |
| `MCP_CONFIG_FILE` | `./config.yaml` | Path to persisted YAML configuration. |
| `MCP_GATEWAY_KEY_PATH` | `./gateway.key` | Path to the age X25519 identity used to encrypt `auth.github_client_secret`. |
| `MCP_GATEWAY_MASTER_KEY` | none | Optional deterministic key seed. Use 32+ random bytes encoded as a string, for example `openssl rand -base64 32`. Used only when creating `gateway.key`. |
| `MCP_MASTER_KEY` | none | Legacy alias for `MCP_GATEWAY_MASTER_KEY`. |
| `MCP_GATEWAY_PUBLIC_URL` | `http://127.0.0.1:<port>` | Canonical client-visible URL used for OAuth callbacks, discovery metadata, and Protected Resource Metadata. |
| `MCP_GATEWAY_BIND_ADDR` | `127.0.0.1:<port>` | TCP listener address. Use `0.0.0.0:<port>` inside Docker when publishing ports. |
| `MCP_GATEWAY_PORT` | `8080` | Port used to derive default `public_url` and `bind_addr` when those settings are not explicit. |
| `MCP_GATEWAY_BASE_URL` | none | Deprecated alias for `MCP_GATEWAY_PUBLIC_URL`. Emits a startup warning when set. |
| `MCP_GATEWAY_TRUSTED_PROXIES` | none | Comma-separated CIDR list for immediate reverse proxies whose `X-Forwarded-*` headers are trusted. |
| `MCP_GATEWAY_TOKEN_STORE_PATH` | `/data/tokens.json` | Persistent token store path. Set to an empty value to disable persistence. |
| `MCP_GATEWAY_TOKEN_AUDIENCE_STRICT` | `false` | Reject legacy tokens that have no recorded audience metadata. Leave disabled during migration. |
| `LOG_LEVEL` | `info` | JSON log level: `debug`, `info`, `warn`, or `error`. |
| `SESSION_TTL_MIN` | `10` | OAuth authorization session lifetime in minutes. |
| `TOKEN_CACHE_TTL_MIN` | `30` | In-memory validation cache TTL in minutes. Used when token persistence is disabled. |
| `TOKEN_EXPIRES_IN_SEC` | `7776000` | Token lifetime advertised to clients and persistent token entry TTL. Default is 90 days. |
| `GITHUB_MCP_UPSTREAM_URL` | none | Deprecated single-upstream fallback when no `ROUTE_*` or `routes:` entries exist. |

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
| `auth.github_client_id` | GitHub OAuth App client ID. |
| `auth.github_client_secret` | GitHub OAuth App client secret. May be encrypted as `ENC[age:]...`; plaintext is encrypted and rewritten on startup. |
| `gateway.public_url` | Canonical public URL visible to OAuth and MCP clients. |
| `gateway.bind_addr` | TCP listener address. |
| `gateway.base_url` | Deprecated alias for `gateway.public_url`. |
| `gateway.port` | Port used when deriving defaults. |
| `gateway.oauth_scopes` | OAuth scopes requested from GitHub. |
| `gateway.trusted_proxies` | CIDR list for trusted reverse proxy peers. |
| `gateway.token_audience_strict` | Strict legacy-token audience enforcement. |
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
ROUTE_COPILOT_REVIEW=/mcp/copilot-review|http://copilot-review-mcp:8083
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
   - No config secret plus `GITHUB_MCP_CLIENT_SECRET`: encrypt, save to config, and use.
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

By default, validated token state is stored in `/data/tokens.json`, which is
created in the Docker image. For non-Docker runs, set a writable path:

```bash
MCP_GATEWAY_TOKEN_STORE_PATH=./tokens.json
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

## OAuth Resource Parameters

The gateway supports RFC 8707 `resource` parameters on:

- `/authorize`
- `/device_authorization`
- `/token` with `grant_type=refresh_token`

The resource must match a registered gateway or route audience. During the
migration grace period, legacy tokens without recorded audience metadata are
accepted while `MCP_GATEWAY_TOKEN_AUDIENCE_STRICT=false`.
