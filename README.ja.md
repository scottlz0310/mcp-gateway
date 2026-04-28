# mcp-gateway

MCP サービス群への統合ゲートウェイ（GitHub OAuth 認証・リクエストルーティング・Fly.io デプロイ対応）

## 概要

`mcp-gateway` は複数の MCP サービスへのリクエストルーティングと GitHub OAuth 2.0 認証を一元管理するリバースプロキシです。`github-oauth-proxy` の後継として設計されています（[Mcp-Docker#102](https://github.com/scottlz0310/Mcp-Docker/issues/102)）。

## アーキテクチャ

```
MCP クライアント
      │
      ▼
mcp-gateway (:8080)
  ├── OAuth フロー   (/authorize, /callback, /token, /register)
  ├── Bearer 検証   (GitHub API キャッシュ付き)
  └── ルーティング
        ├── /mcp/github       → github-mcp:8082
        └── /mcp/copilot-review → copilot-review-mcp:8083
```

## 設定

### 必須環境変数

| 変数 | 説明 |
|------|------|
| `GITHUB_MCP_CLIENT_ID` | GitHub OAuth App の Client ID |
| `GITHUB_MCP_CLIENT_SECRET` | GitHub OAuth App の Client Secret |

### ルーティング設定

`ROUTE_<NAME>=<prefix>|<upstream_url>` の形式で設定します。

```bash
ROUTE_GITHUB=/mcp/github|http://github-mcp:8082
ROUTE_COPILOT_REVIEW=/mcp/copilot-review|http://copilot-review-mcp:8083
```

複数のルートを設定した場合、**最長プレフィックスが優先**されます。

### オプション環境変数

| 変数 | デフォルト | 説明 |
|------|-----------|------|
| `MCP_GATEWAY_BASE_URL` | `http://localhost:8080` | OAuth コールバック等に使用するベース URL |
| `MCP_GATEWAY_PORT` | `8080` | リスンポート |
| `GITHUB_MCP_OAUTH_SCOPES` | `repo,user` | GitHub OAuth スコープ |
| `LOG_LEVEL` | `info` | ログレベル (`debug`/`info`/`warn`/`error`) |
| `SESSION_TTL_MIN` | `10` | OAuth セッション有効期間（分） |
| `TOKEN_CACHE_TTL_MIN` | `30` | トークンキャッシュ有効期間（分） |
| `TOKEN_EXPIRES_IN_SEC` | `7776000` | クライアントへ通知するトークン有効期限（秒、デフォルト 90 日） |
| `GITHUB_MCP_UPSTREAM_URL` | — | **非推奨**: 単一アップストリーム（`ROUTE_*` 未設定時のフォールバック） |

## エンドポイント

| パス | メソッド | 説明 |
|------|---------|------|
| `/.well-known/oauth-authorization-server` | GET | RFC 8414 メタデータ |
| `/authorize` | GET | OAuth 認可エンドポイント |
| `/callback` | GET | GitHub OAuth コールバック |
| `/token` | POST | トークンエンドポイント（PKCE 対応） |
| `/register` | POST | RFC 7591 動的クライアント登録（疑似） |
| `/health` | GET | ヘルスチェック |
| `/<prefix>` | ANY | Bearer 検証後、対応アップストリームへリバースプロキシ |

## クイックスタート

### 1. GitHub OAuth App の作成

**GitHub → Settings → Developer settings → OAuth Apps → New OAuth App** から:

- **Authorization callback URL**: `http://localhost:8080/callback` (または `MCP_GATEWAY_BASE_URL` + `/callback`)

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
      MCP_GATEWAY_BASE_URL: http://localhost:8080
      ROUTE_GITHUB: /mcp/github|http://github-mcp:8082
    depends_on:
      - github-mcp
```

### 2a. マルチアップストリーム: github-mcp + copilot-review-mcp

`ROUTE_*` を複数設定することで、単一ゲートウェイから複数の MCP サービスをルーティングできます。
`copilot-review-mcp` を含む完全な例は [`examples/copilot-review-routing/`](examples/copilot-review-routing/) を参照してください。

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

> **動作原理**: `copilot-review-mcp` は Go の `ServeMux` サブツリーハンドラ (`/mcp/`) を使用しているため、
> mcp-gateway が転送する `/mcp/copilot-review` パスは **`copilot-review-mcp` のコード変更なし** で正しくハンドルされます。

### 3. MCP クライアントの設定

MCP クライアント設定ファイル（例: `claude_desktop_config.json`）に追加してください:

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

## 開発

```bash
# テスト
go test ./...

# ビルド
go build ./cmd/server

# Docker ビルド
docker build -t mcp-gateway .
```
