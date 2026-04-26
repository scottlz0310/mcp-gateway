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

## 開発

```bash
# テスト
go test ./...

# ビルド
go build ./cmd/server

# Docker ビルド
docker build -t mcp-gateway .
```

## Docker Image

```
ghcr.io/scottlz0310/mcp-gateway:latest
```
