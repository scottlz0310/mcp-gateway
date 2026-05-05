# Changelog

すべての変更は [Keep a Changelog](https://keepachangelog.com/ja/1.1.0/) に従い、
バージョニングは [Semantic Versioning](https://semver.org/lang/ja/) に従う。

## [Unreleased]

### Added

- Device Flow の per-device ポーリング直列化 ([#16](https://github.com/scottlz0310/mcp-gateway/issues/16))
  - `internal/auth.Store` に `AcquireDevicePolling` / `ReleaseDevicePolling` を追加し、同一 `device_code` に対する GitHub ポーリングを 1 リクエストのみに制限
  - in-flight 中に届いた並列リクエストは即座に `authorization_pending` を返すため、GitHub の `slow_down` / レート制限（RFC 8628 §3.5）を誘発しない

- v0.1.0 受け入れ E2E ランブック ([`docs/runbook-e2e-v0.1.0.md`](docs/runbook-e2e-v0.1.0.md))
  - 11 シナリオを順序依存で構成: 初回 setup wizard → 再起動を跨いだ config 暗号化往復 → `gateway.key` 破損時の起動拒否 → `MCP_GATEWAY_MASTER_KEY` 決定論的導出 → Authorization Code + PKCE → longest-prefix ルーティング & `X-Authenticated-User` 注入 → `refresh_token` ローテーション → 永続トークンストアによる再認証スキップ → 並列ポーリング下の Device Authorization Grant → ルート単位の `auth=none` バイパス → RFC 6750 / RFC 9728 `WWW-Authenticate` セマンティクス
  - 各シナリオに「期待される挙動」「観測された挙動（記入欄）」、結果サマリ表、失敗時の issue テンプレ、部分再実行用クリーンアップ手順を収録
  - v0.2.0 リリースゲートとして使用する

### Changed

- `tasks.md` を v0.1.0 リリース後の実装状態に同期
  - #11 Config Persistence ([PR #37](https://github.com/scottlz0310/mcp-gateway/pull/37)) と #12 Setup Wizard ([PR #38](https://github.com/scottlz0310/mcp-gateway/pull/38)) を完了反映、サブタスクを `[x]` 化
  - 「推奨消化順」ヘッダを v0.1.0 リリース済みビューに刷新
  - **v0.2.0 ロードマップ** を新規起票（RM1〜RM6）: RM1 v0.1.0 E2E 動作検証（リリースゲート）・RM2 観測性整備・RM3 CI 強化（カバレッジ・golangci-lint・govulncheck）・RM4 ドキュメント整備・RM5 保留 issue 最終判断（#3/#4/#5/#6）・RM6 v0.2.0 リリース。各 RM の個別 issue 化は着手直前に判断する方針

> **注**: 英語版 [`CHANGELOG.md`](CHANGELOG.md) の `[Unreleased]` には #11 / #12 の項目が記載されているが、本日本語版には未記載のまま。これは別途同期する（本変更のスコープ外）。

## [0.1.0] - 2026-04-30

### Added

- Device Authorization Grant (RFC 8628) 実装 ([#10](https://github.com/scottlz0310/mcp-gateway/issues/10))
  - `POST /device_authorization` エンドポイント: gateway が GitHub に Device Flow を開始し、`user_code` と `verification_uri` をクライアントに返す
  - `POST /token` を `grant_type` に応じてディスパッチするよう拡張（`authorization_code` / `urn:ietf:params:oauth:grant-type:device_code`）
  - `/.well-known/oauth-authorization-server` に `device_authorization_endpoint` と `urn:ietf:params:oauth:grant-type:device_code` grant type を追加
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
