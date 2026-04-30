# Changelog

すべての変更は [Keep a Changelog](https://keepachangelog.com/ja/1.1.0/) に従い、
バージョニングは [Semantic Versioning](https://semver.org/lang/ja/) に従う。

## [Unreleased]

## [0.1.0] - 2026-04-30

### Added

- Device Authorization Grant (RFC 8628) 実装 ([#10](https://github.com/scottlz0310/mcp-gateway/issues/10))
  - `POST /device_authorization` エンドポイント: gateway が GitHub に Device Flow を開始し、`user_code` と `verification_uri` をクライアントに返す
  - `POST /token` を `grant_type` に応じてディスパッチするよう拡張（`authorization_code` / `urn:ietf:params:oauth:grant-type:device_code`）
  - `/.well-known/oauth-authorization-server` に `device_authorization_endpoint` と `device_code` grant type を追加
  - `internal/auth.Store` に `DeviceSession` 管理（CreateDevice / GetDevice / AuthorizeAndConsumeDevice / DenyDevice）を追加
  - `AuthorizeAndConsumeDevice` による TOCTOU 排除：トークン記録とセッション削除を単一 Lock で atomic に実行
- ルート単位の認証バイパス: `ROUTE_*` の値に `|auth=none` を追加することで、特定ルートの Bearer 検証をスキップ可能 ([#22](https://github.com/scottlz0310/mcp-gateway/issues/22), [PR #23](https://github.com/scottlz0310/mcp-gateway/pull/23))
  - 例: `ROUTE_PUBLIC=/public|http://public-svc:8083|auth=none`
- `MCP_GATEWAY_TOKEN_STORE_PATH` による永続トークンストア ([#24](https://github.com/scottlz0310/mcp-gateway/issues/24), [PR #25](https://github.com/scottlz0310/mcp-gateway/pull/25))
  - SHA-256 ハッシュ済みキーによるファイルストア（生トークンはディスクに書き込まれない）
  - gateway 再起動後も認証状態を維持; エントリは `TOKEN_EXPIRES_IN_SEC`（デフォルト 90 日）で失効
  - パス未設定時はインメモリストアにフォールバック
- リフレッシュトークングラント: `POST /token` が `grant_type=refresh_token` をサポート（シングルユース ローテーション）([#26](https://github.com/scottlz0310/mcp-gateway/issues/26), [PR #27](https://github.com/scottlz0310/mcp-gateway/pull/27))
- マルチアップストリーム例: `examples/copilot-review-routing/` — 単一の mcp-gateway で `github-mcp-server` と `copilot-review-mcp` 両方を `ROUTE_GITHUB` / `ROUTE_COPILOT_REVIEW` でルーティング（[#19](https://github.com/scottlz0310/mcp-gateway/issues/19)）
  - `copilot-review-mcp` 側のコード変更ゼロで動作（Go `ServeMux` の `/mcp/` サブツリーハンドラが転送パスに正しくマッチ）
  - `docker-compose.yml`・`.env.example`・専用 `README.md` を含む

### Changed

- `internal/auth` を `Provider` インターフェースで抽象化。GitHub OAuth 通信ロジックを `internal/auth/provider/github.go` に分離した。外部 IF（環境変数・エンドポイント・OAuth フロー）は変更なし（[#2](https://github.com/scottlz0310/mcp-gateway/issues/2)）。
- リバースプロキシが上流 MCP サービスに送出するヘッダに `X-Authenticated-User` を追加。`X-GitHub-Login` も互換のため引き続き送出する（[#2](https://github.com/scottlz0310/mcp-gateway/issues/2)）。

### Fixed

- Docker イメージに `/data` ディレクトリを事前作成。`MCP_GATEWAY_TOKEN_STORE_PATH=/data/tokens.json` がディレクトリの手動作成なしで動作するよう修正 ([#28](https://github.com/scottlz0310/mcp-gateway/issues/28), [PR #29](https://github.com/scottlz0310/mcp-gateway/pull/29))
- `.gitignore` に `*.exe` を追加（Windows ビルド成果物を除外）

### Internal

- `auth.Handler` から GitHub 固有の HTTP 通信を排除し、`provider.Provider` への委譲に変更。
- `middleware` のコンテキストキーを `github_login` → `authenticated_user` に rename（内部実装のみ、外部互換維持）。

[Unreleased]: https://github.com/scottlz0310/mcp-gateway/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/scottlz0310/mcp-gateway/releases/tag/v0.1.0
