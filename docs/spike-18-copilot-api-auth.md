# Spike #18: `https://api.githubcopilot.com/mcp/` Upstream 認証互換性調査

## 概要

mcp-gateway の upstream として `https://api.githubcopilot.com/mcp/` を使用した場合の
認証・ルーティング互換性を検証したスパイクの調査結果をまとめる。

---

## 調査方法

curl コマンドによる直接検証（2026-04-28 実施）。

---

## 調査結果

### 1. OAuth Discovery

`https://api.githubcopilot.com/.well-known/oauth-authorization-server` → **404**（ルートには存在しない）

WWW-Authenticate ヘッダで参照される実際の Resource Metadata URL:

```
https://api.githubcopilot.com/.well-known/oauth-protected-resource/mcp/
```

### 2. Resource Metadata (`/mcp/` サブパス)

```json
{
  "resource": "https://api.githubcopilot.com/mcp/",
  "authorization_servers": ["https://github.com/login/oauth"],
  "scopes_supported": [
    "repo", "read:org", "read:user", "user:email",
    "read:packages", "write:packages", "read:project",
    "project", "gist", "notifications", "workflow",
    "codespace"
  ],
  "bearer_methods_supported": ["header"],
  "resource_name": "GitHub MCP Server"
}
```

**重要**: `authorization_servers` が `https://github.com/login/oauth` であり、
**標準 GitHub OAuth トークン（`gho_`）が認証に使用可能**。

### 3. 未認証アクセス時のレスポンス

```
HTTP/1.1 401 Unauthorized
www-authenticate: Bearer error="invalid_request",
  error_description="No access token was provided in this request",
  resource_metadata="https://api.githubcopilot.com/.well-known/oauth-protected-resource/mcp/"
Server: github-mcp-server-remote
```

### 4. `gho_` トークンによる直接アクセス検証

```bash
curl -si -H "Authorization: Bearer gho_..." https://api.githubcopilot.com/mcp/
# → HTTP/1.1 405 Method Not Allowed（GET は不可、POST が必要）
# → 401 ではないため認証成功
```

### 5. MCP Initialize (POST) 検証

```bash
curl -si -X POST \
  -H "Authorization: Bearer gho_..." \
  -H "Content-Type: application/json" \
  -H "Accept: application/json, text/event-stream" \
  https://api.githubcopilot.com/mcp/ \
  -d '{"jsonrpc":"2.0","method":"initialize","params":{...},"id":1}'
```

結果:

```
HTTP/1.1 200 OK
Content-Type: text/event-stream
mcp-session-id: e4149ddf-f116-4a3d-a92f-29d9788b8c60
Server: github-mcp-server-remote

event: message
data: {"jsonrpc":"2.0","id":1,"result":{
  "capabilities":{"completions":{},"prompts":{},"resources":{},"tools":{}},
  "protocolVersion":"2024-11-05",
  "serverInfo":{"name":"github-mcp-server","title":"GitHub MCP Server", ...}
}}
```

**`gho_` トークン（scopes: `gist, read:org, repo, workflow`）で MCP initialize が成功することを確認。**

---

## 重要な発見：パスルーティングの挙動

### `(*httputil.ProxyRequest).SetURL` のパス結合動作

mcp-gateway は `Rewrite` 内で `pr.SetURL(upstream)` を使用している。
`(*httputil.ProxyRequest).SetURL` は upstream URL のパスとリクエストパスを `singleJoiningSlash` で結合する。

| upstream URL | リクエストパス | 転送先パス | 結果 |
|---|---|---|---|
| `https://api.githubcopilot.com/mcp/` | `/mcp/` | `/mcp/mcp/` | ❌ パス二重化 |
| `https://api.githubcopilot.com` | `/mcp/` | `/mcp/` | ✅ 正常 |

### 正しい設定方法

```env
# ❌ 誤り：upstream に /mcp/ パスを含めると二重化
ROUTE_COPILOT=/mcp|https://api.githubcopilot.com/mcp/

# ✅ 正しい：upstream はホストのみ（パスなし）
ROUTE_COPILOT=/mcp|https://api.githubcopilot.com
```

---

## 複数ルートの共存

`ROUTE_*` による longest-prefix-first マッチングにより、
Copilot API と他の MCP サービスを同時に運用可能：

```env
# ゲートウェイの /mcp/ → Copilot API
ROUTE_COPILOT=/mcp|https://api.githubcopilot.com

# ゲートウェイの /mcp/copilot-review/ → 自前 MCP サービス（より長いプレフィックスが優先）
ROUTE_COPILOT_REVIEW=/mcp/copilot-review|http://copilot-review-mcp:8083
```

クライアントからのリクエスト分岐：
- `POST /mcp/copilot-review/` → `/mcp/copilot-review/` が `/mcp/` より長いため `copilot-review-mcp` へ
- `POST /mcp/` → `/mcp/` が Copilot API へ

---

## プロトコル互換性

| 項目 | 値 | 互換性 |
|---|---|---|
| MCP Protocol Version | `2024-11-05` | ✅ |
| Transport | SSE (`text/event-stream`) | ✅ (`httputil.ReverseProxy` はストリーミング対応) |
| Session管理 | `mcp-session-id` ヘッダ | ✅ (proxy が透過転送) |
| 認証方式 | Bearer token (header) | ✅ (proxy が `Authorization: Bearer <token>` を注入) |

---

## 既知の制限と注意点

### A. `X-Authenticated-User` / `X-GitHub-Login` ヘッダ注入

proxy ハンドラは upstream への全リクエストに `X-Authenticated-User` および
`X-GitHub-Login` ヘッダを注入する（`internal/proxy/handler.go` の `proxy.NewHandler` における upstream リクエスト生成時のヘッダ設定処理）。
Copilot API はこれらのヘッダを無視するが、予期しない動作の原因になる可能性は低い。

### B. 401 時の `WWW-Authenticate` ヘッダ

upstream が 401 を返した場合、`WWW-Authenticate` ヘッダはそのまま透過される。
このヘッダには `resource_metadata` として `https://api.githubcopilot.com/...` が含まれるため、
クライアントが gateway の OAuth サーバーではなく Copilot API の OAuth サーバーに
再認証を試みる可能性がある。

→ 将来的に `ModifyResponse` で `WWW-Authenticate` を gateway の discovery URL に
  書き換えることを検討すること（Issue を起票して追跡）。

### C. copilot-cli での直接接続失敗の根本原因

ユーザーが報告した「copilot-cli での `https://api.githubcopilot.com/mcp/` への直接接続失敗」は、
トークンの形式の問題ではない（`gho_` トークンでの接続は本調査で確認済み）。
考えられる原因：

1. **OAuth App のスコープ不一致**：copilot-cli が使用する OAuth App と
   Copilot API が要求するスコープが一致しない
2. **MCP client 設定の問題**：`mcp.json` の `url` がゲートウェイを指しており、
   直接 URL に変更しても認証エンドポイントが `/.well-known/oauth-authorization-server`
   を期待するが Copilot API では別パスにある
3. **ネットワーク/プロキシ設定**：法人環境での TLS インスペクション等

mcp-gateway 経由（`github-oauth-proxy`）であれば認証できている現状から、
**ゲートウェイを経由させる構成が最も安定**。

---

## 結論と推奨事項

### 今すぐ使える構成

```env
ROUTE_COPILOT=/mcp|https://api.githubcopilot.com
```

この設定で mcp-gateway を通じて `https://api.githubcopilot.com/mcp/` に
プロキシすることが可能。標準の `gho_` トークンが使用される。

### 既存の copilot-review-mcp との共存 (docker-compose 例)

```yaml
services:
  mcp-gateway:
    environment:
      ROUTE_COPILOT: /mcp|https://api.githubcopilot.com
      ROUTE_COPILOT_REVIEW: /mcp/copilot-review|http://copilot-review-mcp:8083
```

### 中長期的な改善事項

1. `WWW-Authenticate` ヘッダの書き換え（upstream 固有の discovery URL を gateway URL に変換）
2. per-upstream OAuth App 設定（upstream ごとに異なる client_id を使えるようにする）
3. パスプレフィックス除去オプション（`ROUTE_X=/prefix|upstream|strip_prefix=true` のような設定）

---

## 参考資料

- [RFC 8707: Resource Indicators for OAuth 2.0](https://www.rfc-editor.org/rfc/rfc8707)
- [OAuth 2.0 Protected Resource Metadata](https://www.ietf.org/archive/id/draft-ietf-oauth-resource-metadata-13.txt)
- GitHub Copilot MCP: `https://api.githubcopilot.com/mcp/`
- mcp-gateway proxy handler: `internal/proxy/handler.go`
- mcp-gateway router: `internal/router/router.go`
