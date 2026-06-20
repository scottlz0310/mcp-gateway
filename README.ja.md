# mcp-gateway

MCP (Model Context Protocol) サービス群のための統合認証・ルーティングゲートウェイ。

mcp-gateway は GitHub OAuth 2.0 認証、MCP Authorization メタデータ、複数の
上流 MCP サーバーへのリバースプロキシを一元管理します。Claude Desktop や
VS Code などの MCP クライアントから見た単一の HTTP エントリポイントとして動作します。

> [mcp-docker](https://github.com/scottlz0310/Mcp-Docker) エコシステムの一部です。
> `mcp-docker` と `copilot-review-mcp` と組み合わせて利用することを想定しています。

## はじめに

### 1. GitHub App を作成

**GitHub -> Settings -> Developer settings -> GitHub Apps -> New GitHub App** を開きます。

以下の設定を行います。

- **Callback URLs** — 次の 2 つを両方登録します。
  ```text
  http://127.0.0.1:8080/callback
  http://127.0.0.1:8080/device_callback
  ```
  デプロイ環境では `http://127.0.0.1:8080` を `<MCP_GATEWAY_PUBLIC_URL>` に置き換えてください。
- **Permissions** — 推奨設定:

  | カテゴリ | 権限 | アクセス |
  |---------|------|---------|
  | Repository | Metadata | Read-only（自動選択） |
  | Repository | Contents | Read-only |
  | Repository | Issues | Read and write |
  | Repository | Pull requests | Read and write |
  | Account | Email addresses | Read-only |

  `Email addresses` はユーザー識別に必須です。Repository 権限は `review-raven` / `github-mcp-server`
  upstream が必要とします。自分の MCP upstream に合わせて最小限の権限に調整してください。
- **Webhook** — 無効のままにします（OAuth フローでは使用しません）。
- **Where can this GitHub App be installed?** — 個人利用の場合は `Only on this account` を選択します。

作成後、アプリ設定ページで **Client secret** を生成し、**Client ID** と合わせてコピーします。

> **GitHub OAuth App からの移行**: `OAUTH_CLIENT_ID` と `OAUTH_CLIENT_SECRET` を新しい
> GitHub App の認証情報に置き換えるだけで移行できます。コードや設定ファイルの変更は不要です。
> ゲートウェイは `gho_`（OAuth App）と `ghu_`（GitHub App）の両トークンに対応しています。
>
> **トークン有効期限について**: 短命 `ghu_` トークンと自動ローテーションを有効にするには、
> GitHub App の設定で "Expire user authorization tokens" をチェックし、ゲートウェイで
> `MCP_GATEWAY_GITHUB_REFRESH_ENABLED=true` を設定してください。
> 詳細は [docs/configuration.md](docs/configuration.md#github-oauth-refresh-token-rotation) を参照。

### 2. Docker Compose で起動

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
| [thread-owl](https://github.com/scottlz0310/thread-owl) | レビュアー側 MCP サーバー: webhook 受信・レビュー候補判定・キュー管理。 |
| [mcp-resource-subscriber](https://github.com/scottlz0310/mcp-resource-subscriber) | MCP resource 通知のサブスクリプションクライアント兼エージェントワークフロー橋渡し。 |
| [review-raven](https://github.com/scottlz0310/review-raven) | レビューされる側 MCP: Copilot レビュースレッド取得・返信・解決・再レビュー依頼。 |
| [mcp-docker](https://github.com/scottlz0310/Mcp-Docker) | コンテナオーケストレーション、ゲートウェイルート生成、CLI エージェント設定自動化。 |
| [squirrel-notifier](https://github.com/scottlz0310/squirrel-notifier) | デスクトップ常駐の通知受信 / AI エージェントランチャー: mcp-gateway 経由で MCP resource 更新を監視し、トースト通知とローカル AI エージェントの起動を担当。 |

## ドキュメント

| Document | 用途 |
|----------|------|
| [docs/README.md](docs/README.md) | ドキュメント index。 |
| [docs/architecture.md](docs/architecture.md) | レビュープラットフォーム概要、責務境界、設計原則。 |
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
- **upstream OAuth 委任**: ルート単位で upstream OAuth を設定。`authorization_code`（ユーザー認可フロー）または `client_credentials`（サービス間通信）を選択可能。AS の自動検出（RFC 9728 + RFC 8414）・Dynamic Client Registration・ユーザーごとのトークン永続化・proactive refresh・透過的 401 retry に対応。

## 主要設定

最小 Docker 環境:

```yaml
environment:
  OAUTH_CLIENT_ID: <your-client-id>
  OAUTH_CLIENT_SECRET: <your-client-secret>
  MCP_GATEWAY_BIND_ADDR: 0.0.0.0:8080
  MCP_GATEWAY_PUBLIC_URL: http://127.0.0.1:8080
  ROUTE_GITHUB: /mcp/github|http://github-mcp:8082
```

重要な path:

| Setting | Default | Notes |
|---------|---------|-------|
| `MCP_CONFIG_FILE` | `{state-dir}/config.yaml` | setup 結果と暗号化 secret。 |
| `MCP_GATEWAY_KEY_PATH` | `{state-dir}/gateway.key` | age X25519 identity。安全にバックアップしてください。 |
| `MCP_GATEWAY_TOKEN_STORE_PATH` | `{state-dir}/tokens.json` | token 永続化 path。Docker 環境では環境変数で上書きすること。 |
| `MCP_GATEWAY_AUTH_AUDIT_LOG_PATH` | OS のユーザー state 領域。公式 image では `/data/mcp-gateway/logs/auth-audit.jsonl` | OAuth 監査 JSON Lines。相対 path と Git worktree 配下は拒否されます。 |
| *(自動生成)* | `{state-dir}/upstream_clients.json` | upstream AS の Dynamic Client Registration 記録（mode 0600）。upstream OAuth ルートへの初回アクセス時に作成。 |
| *(自動生成)* | `{state-dir}/upstream_tokens.json` | ユーザーごとの upstream OAuth access/refresh token（mode 0600）。初回 upstream OAuth 認可完了時に作成。 |

`{state-dir}` は起動時に解決される OS ユーザー状態ディレクトリです（Windows: `%LOCALAPPDATA%\mcp-gateway`、macOS: `~/Library/Application Support/mcp-gateway`、Linux: `$XDG_STATE_HOME/mcp-gateway` → `~/.local/state/mcp-gateway`）。Docker 環境では必ず環境変数でパスを上書きしてください。詳細は [docs/configuration.md](docs/configuration.md) を参照してください。

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
| `/upstream/callback/{routeName}` | GET | upstream OAuth authorization code callback（`authorization_code` フロー専用）。 |
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
