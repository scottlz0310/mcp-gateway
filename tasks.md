# Tasks

`mcp-gateway` の継続的なタスク管理ファイル。各 issue の状態とサブタスク、依存関係を記録する。

## 凡例

- `[ ]` 未着手
- `[~]` 進行中
- `[x]` 完了
- `[-]` 保留 / 別 issue へ移管

---

## Issue 一覧

### [#2 refactor: OAuth プロバイダ抽象化（Provider インターフェース導入・GitHub 実装の移植）](https://github.com/scottlz0310/mcp-gateway/issues/2)

**状態**: 実装完了・PR レビュー中
**ブランチ**: `refactor/oauth-provider-abstraction`
**依存**: なし

GitHub 固定の OAuth フローを `Provider` インターフェースに抽象化。本 issue は **GitHub-only リファクタ**に限定し、外部 IF（環境変数・エンドポイント・OAuth フロー）は 100% 維持する。

#### サブタスク

- [x] `internal/auth/provider/provider.go` — `Provider` IF + `Identity` 構造体
- [x] `internal/auth/provider/errors.go` — `UpstreamError` 移設
- [x] `internal/auth/provider/github.go` — GitHub 実装（既存ロジック移植）
- [x] `internal/auth/provider/factory.go` — `New(cfg) (Provider, error)`
- [x] `internal/auth/provider/mock.go` — テスト用 Mock
- [x] `internal/auth/provider/github_test.go` — GitHub 実装の単体テスト
- [x] `internal/auth/handler.go` — Provider 委譲、Config から GitHub 専用フィールド除去
- [x] `internal/middleware/auth.go` — `ContextKeyIdentity` へ rename
- [x] `internal/proxy/handler.go` — `X-Authenticated-User` 注入（`X-GitHub-Login` も互換併存）
- [x] `cmd/server/main.go` — Provider factory 経由で生成
- [x] `README.md` — 内部設計の補足
- [x] `CHANGELOG.md` — 変更履歴記載
- [x] テスト緑（`go test ./...`）

---

### [#3 spike: fly.io 認証方式の調査（OAuth Provider vs Macaroon Tokens）](https://github.com/scottlz0310/mcp-gateway/issues/3)

**状態**: 調査完了（2026-04-27）
**依存**: なし

**結論**: Sign in with Fly（OAuth 2.0）を Issue #4 で採用。Macaroon は Provider IF 不適合のため対象外。Provider IF（#2 で確定）に変更不要。詳細は Issue #3 本文参照。

#### サブタスク

- [x] fly.io OAuth Provider の `authorize` / `token` / userinfo エンドポイント仕様確認
- [x] fly.io OAuth App 登録手段の確認（self-service 不可・fly.io と直接調整）
- [x] Fly Tokens（Macaroon）検証手段の確認（`superfly/macaroon` + tkdb・外部利用非推奨）
- [x] mcp-gateway のユースケースに必要な系統の確定（Sign in with Fly）
- [-] 調査メモ作成（`docs/spikes/flyio-auth.md`）→ Issue #3 本文に集約
- [x] Issue #2 / #4 へのフィードバック（IF 変更不要・#4 前提条件を本文に記載）

---

### [#4 feat: fly.io OAuth プロバイダ実装](https://github.com/scottlz0310/mcp-gateway/issues/4)

**状態**: 保留（2026-04-27）
**依存**: #2, #3
**保留理由**: fly.io OAuth（Sign in with Fly）は Extensions Provider 専用であり、開発用 client_id/client_secret の self-service 登録手段がない。fly.io と直接調整が必要なため、プロダクト品質が整うまで後回し。代替 OAuth プロバイダの検討を優先する。

#### サブタスク

- [-] `internal/auth/provider/flyio.go` 実装（保留）
- [-] `internal/auth/provider/factory.go` の `flyio` 分岐追加（保留）
- [-] 単体テスト追加（保留）
- [-] README に fly.io 設定例追記（保留）

---

### [#5 refactor: 環境変数を OAUTH_* 系に移行・GITHUB_MCP_* を deprecate](https://github.com/scottlz0310/mcp-gateway/issues/5)

**状態**: 保留（2026-04-27）
**依存**: #2
**保留理由**: 追加プロバイダがすべて保留・クローズとなったため優先度低下。プロバイダ追加が確定した時点で再開。

#### サブタスク

- [-] `OAUTH_PROVIDER` / `OAUTH_CLIENT_ID` / `OAUTH_CLIENT_SECRET` / `OAUTH_SCOPES` を導入（保留）
- [-] `GITHUB_MCP_*` の後方互換ロジック追加（warning 付き）（保留）
- [-] README 環境変数表の更新（保留）
- [-] CHANGELOG に移行ガイド記載（保留）

---

### [#8 feat: Google OAuth 2.0 プロバイダ実装](https://github.com/scottlz0310/mcp-gateway/issues/8)

**状態**: クローズ（2026-04-27・YAGNI）
**理由**: Google 公式 MCP サーバーは OAuth + Streamable HTTP を既に内包。対象 MCP サーバーが具体的に決まるまで見送り。

---

### [#6 feat: 汎用 OIDC（OpenID Connect）プロバイダサポート](https://github.com/scottlz0310/mcp-gateway/issues/6)

**状態**: 保留（2026-04-27）
**依存**: #2
**保留理由**: Entra ID は DCR 未サポートで MCP OAuth 2.1 仕様と不適合。対象 MCP サーバーが具体的に決まるまで見送り（YAGNI）。

#### サブタスク

- [-] `internal/auth/provider/oidc.go` 実装（保留）
- [-] OIDC Discovery + JWKS フェッチ（保留）
- [-] ID Token 検証（署名・クレーム）（保留）
- [-] 環境変数追加（`OAUTH_ISSUER_URL`, `OAUTH_AUDIENCE` 等）（保留）
- [-] Auth0 / Keycloak での結合テスト（保留）

---

### [#10 spike: Device Authorization Grant を gateway レイヤーで実装する可能性調査](https://github.com/scottlz0310/mcp-gateway/issues/10)

**状態**: 未着手
**依存**: #2（完了済み）、#11（config persistence）

"OAuthログインで全認証完了" を実現するための前調査。Device Grant は **gateway が実行する**アーキテクチャを採用する。

**確定アーキテクチャ:**
```
MCP Client → mcp-gateway（Device Grant 実行）→ GitHub
```

MCPクライアント直の Device Grant（gateway は validation のみ）は**採用しない**（トークン分散・セッション非共有・refresh管理破綻のため）。

#### サブタスク

- [ ] GitHub Device Grant エンドポイント（`client_secret` 要否）の確認
- [ ] gateway 内 Device Grant フロー設計（`POST /auth/device`・`GET /auth/device/poll`）
- [ ] MCP Authorization Server Metadata への `device_authorization_endpoint` 追加検討
- [ ] VS Code Copilot 拡張が Device Grant を実際に利用するか動作確認
- [ ] 既存 Authorization Code Flow との共存設計
- [ ] 後続実装 ISSUE のスコープ・前提条件確定

---

### [#11 feat: Config Persistence Layer（env vars → YAML/SQLite 設定ファイル）](https://github.com/scottlz0310/mcp-gateway/issues/11)

**状態**: 未着手
**依存**: なし（独立着手可能）

`mustEnv` によるクラッシュを撤廃し、設定を YAML / SQLite で永続管理する。env vars はオーバーライド手段として維持（12-factor 互換）。

#### サブタスク

- [ ] `internal/config/` パッケージ新設（Config 構造体・YAML 読み書き・env override マージ）
- [ ] 設定ファイルパス解決（`MCP_CONFIG_FILE` env > XDG > デフォルト）
- [ ] `cmd/server/main.go` の `mustEnv` を config ロードに置き換え
- [ ] `internal/router/router.go` の `ParseEnv()` を config ベース実装に切り替え
- [ ] SQLite ルートストアの設計・実装（CRUD）
- [ ] `internal/auth/session.go` のトークン永続化対応
- [ ] テスト / README.md / CHANGELOG.md 更新

---

### [#12 feat: First-run Setup Wizard（初回デプロイ時のインタラクティブ設定フロー）](https://github.com/scottlz0310/mcp-gateway/issues/12)

**状態**: 未着手
**依存**: #11（Config Persistence Layer）

設定ファイルが存在しない初回起動時に `/setup` エンドポイントを自動活性化し、ブラウザ or CLI で初期設定を完了できるようにする。

起動フロー:
```
設定なし → setup_token を stdout に出力 → GET /setup?token=<token> → POST /setup → 設定完了 → 通常起動
```

#### サブタスク

- [ ] `internal/setup/` パッケージ新設（token 生成・検証・一度限り保証）
- [ ] `setup_completed` フラグの config 統合（#11 依存）
- [ ] `GET /setup` / `POST /setup` ハンドラ実装
- [ ] 起動ログへの setup_token 出力（`log/slog`）
- [ ] 未 setup 状態での通常ルートのレスポンス
- [ ] HTTPS チェック（production 判定）
- [ ] テスト / README.md（first-run guide 書き換え） / CHANGELOG.md 更新
