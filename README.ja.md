# mcp-gateway

MCP (Model Context Protocol) サービス群のための統合認証・ルーティングゲートウェイ。

mcp-gateway は GitHub OAuth 2.0 認証、MCP Authorization メタデータ、複数の
上流 MCP サーバーへのリバースプロキシを一元管理します。Claude Desktop や
VS Code などの MCP クライアントから見た単一の HTTP エントリポイントとして動作します。

> [mcp-docker](https://github.com/scottlz0310/Mcp-Docker) エコシステムの一部です。
> `mcp-docker` と `copilot-review-mcp` と組み合わせて利用することを想定しています。

## はじめに

### 1. GitHub OAuth App を作成

**GitHub -> Settings -> Developer settings -> OAuth Apps -> New OAuth App** を開きます。

ローカル開発では callback URL に次を設定します。

```text
http://127.0.0.1:8080/callback
```

デプロイ環境では `<MCP_GATEWAY_PUBLIC_URL>/callback` を設定します。

### 2. Docker Compose で起動

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

フル構成の Compose スタックは
[mcp-docker](https://github.com/scottlz0310/Mcp-Docker) を参照してください。

### 3. MCP クライアントを設定

MCP クライアント設定例:

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

複数の上流を使う場合は `ROUTE_*` を追加し、各 MCP server の URL を対応ルートに向けます。

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

完全なマルチアップストリーム例は
[`examples/copilot-review-routing/`](examples/copilot-review-routing/) にあります。

### 4. ヘルスチェック

```bash
curl -fsS http://127.0.0.1:8080/health
```

期待レスポンス:

```json
{"status":"ok"}
```

## 仕組み

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

mcp-gateway は `github-oauth-proxy` の後継です
([Mcp-Docker#102](https://github.com/scottlz0310/Mcp-Docker/issues/102))。

### リポジトリ構成

| Repo | 役割 |
|------|------|
| **mcp-gateway** | OAuth 2.0 認証、MCP authorization metadata、トークン永続化、ルーティングゲートウェイ。 |
| [mcp-docker](https://github.com/scottlz0310/Mcp-Docker) | MCP スタック全体の Docker Compose オーケストレーション。 |
| [copilot-review-mcp](https://github.com/scottlz0310/copilot-review-mcp) | Copilot コードレビュー MCP サーバー。 |

## ドキュメント

| Document | 用途 |
|----------|------|
| [docs/README.md](docs/README.md) | ドキュメント index。 |
| [docs/configuration.md](docs/configuration.md) | 環境変数、`config.yaml`、ルート、トークンストア、リバースプロキシ、エンドポイントの詳細リファレンス。 |
| [docs/operations.md](docs/operations.md) | 起動停止、ヘルスチェック、構造化ログ、トラブルシュート、移行手順。 |
| [docs/runbook-e2e-v0.1.0.md](docs/runbook-e2e-v0.1.0.md) | E2E 受け入れランブック。 |

## 初回起動セットアップウィザード

GitHub client ID、GitHub client secret、ルート設定のいずれかが不足している場合、
gateway は終了せずセットアップモードに入ります。

動作:

1. gateway は通常の bind address で待ち受けます。
2. 15 分 TTL のワンタイム setup token が stdout に出力されます。
3. `/setup` 以外のパスは `503 setup_required` を返します。

セットアップ例:

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

`POST` 成功後、gateway は `config.yaml` を書き込み、secret を age で暗号化し、
setup token を消費して終了コード 0 で終了します。その後 supervisor が通常モードで再起動します。

運用時の詳細と復旧手順は [docs/operations.md](docs/operations.md) を参照してください。

## 主な機能

- GitHub OAuth 2.0 authorization code + PKCE。
- Device Authorization Grant と refresh token grant。
- RFC 8414 authorization server metadata。
- RFC 9728 Protected Resource Metadata とルート単位 PRM。
- RFC 8707 `resource` parameter による audience 付き token。
- MCP クライアント向け dynamic client registration endpoint。
- 最長 prefix match による複数 upstream ルーティング。
- 明示的な公開 route 用の `auth=none` bypass。
- access token / refresh token 状態の永続化。
- GitHub OAuth client secret の age X25519 暗号化保存。
- request、auth、setup、proxy event の構造化 JSON log。
- TLS 終端 proxy 向け trusted reverse proxy header 処理。

## 主要設定

最小 Docker 環境:

```yaml
environment:
  GITHUB_MCP_CLIENT_ID: <your-client-id>
  GITHUB_MCP_CLIENT_SECRET: <your-client-secret>
  MCP_GATEWAY_BIND_ADDR: 0.0.0.0:8080
  MCP_GATEWAY_PUBLIC_URL: http://127.0.0.1:8080
  ROUTE_GITHUB: /mcp/github|http://github-mcp:8082
```

重要な path:

| Setting | Default | Notes |
|---------|---------|-------|
| `MCP_CONFIG_FILE` | `./config.yaml` | setup 結果と暗号化 secret。 |
| `MCP_GATEWAY_KEY_PATH` | `./gateway.key` | age X25519 identity。安全にバックアップしてください。 |
| `MCP_GATEWAY_TOKEN_STORE_PATH` | `/data/tokens.json` | Docker 向け token 永続化 path。Docker 以外では書き込み可能な path を指定してください。 |

詳細は [docs/configuration.md](docs/configuration.md) を参照してください。

## エンドポイント

| Path | Method | Description |
|------|--------|-------------|
| `/.well-known/oauth-authorization-server` | GET | Authorization server metadata。 |
| `/.well-known/oauth-protected-resource` | GET | gateway 全体の Protected Resource Metadata。 |
| `/.well-known/oauth-protected-resource/<prefix>` | GET | ルート単位の Protected Resource Metadata。例: `/.well-known/oauth-protected-resource/mcp/github` |
| `/authorize` | GET | OAuth authorization endpoint。 |
| `/callback` | GET | GitHub OAuth callback。 |
| `/device_authorization` | POST | Device Authorization Grant endpoint。 |
| `/token` | POST | authorization code、device code、refresh token grant。 |
| `/register` | POST | Dynamic client registration。 |
| `/setup` | GET/POST | setup mode 中の初回起動 wizard。 |
| `/health` | GET | 通常モードの health check。 |
| `/<prefix>` | ANY | マッチした upstream への reverse proxy。 |

## 内部設計

OAuth provider 固有処理は `Provider` interface の後ろに分離されています。

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

proxy は認証済み identity を上流 MCP server に転送します。

| Header | Value |
|--------|-------|
| `X-Authenticated-User` | provider 非依存の authenticated subject。 |
| `X-GitHub-Login` | legacy upstream 互換のため同じ値を送出。 |

なりすまし可能な identity header と forwarded header は proxy 前に削除されます。

## 開発

```bash
go test ./...
go build ./cmd/server
docker build -t mcp-gateway .
```

## Docker イメージ

```text
ghcr.io/scottlz0310/mcp-gateway:latest
```

image は `gcr.io/distroless/static-debian12:nonroot` ベースで、UID 65532 として動作します。

## ライセンス

[LICENSE](LICENSE) を参照してください。
