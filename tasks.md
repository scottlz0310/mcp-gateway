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

**状態**: 未着手
**依存**: なし（#2 と並行可能）

#### サブタスク

- [ ] fly.io OAuth Provider の `authorize` / `token` / userinfo エンドポイント仕様確認
- [ ] fly.io OAuth App 登録手段の確認
- [ ] Fly Tokens（Macaroon）検証手段の確認
- [ ] mcp-gateway のユースケースに必要な系統の確定
- [ ] 調査メモ作成（`docs/spikes/flyio-auth.md`）
- [ ] Issue #2 / #4 へのフィードバック

---

### [#4 feat: fly.io OAuth プロバイダ実装](https://github.com/scottlz0310/mcp-gateway/issues/4)

**状態**: 未着手
**依存**: #2, #3

#### サブタスク

- [ ] `internal/auth/provider/flyio.go` 実装
- [ ] `internal/auth/provider/factory.go` の `flyio` 分岐追加
- [ ] 単体テスト追加
- [ ] README に fly.io 設定例追記

---

### [#5 refactor: 環境変数を OAUTH_* 系に移行・GITHUB_MCP_* を deprecate](https://github.com/scottlz0310/mcp-gateway/issues/5)

**状態**: 未着手
**依存**: #2

#### サブタスク

- [ ] `OAUTH_PROVIDER` / `OAUTH_CLIENT_ID` / `OAUTH_CLIENT_SECRET` / `OAUTH_SCOPES` を導入
- [ ] `GITHUB_MCP_*` の後方互換ロジック追加（warning 付き）
- [ ] README 環境変数表の更新
- [ ] CHANGELOG に移行ガイド記載

---

### [#6 feat: 汎用 OIDC（OpenID Connect）プロバイダサポート](https://github.com/scottlz0310/mcp-gateway/issues/6)

**状態**: 未着手
**依存**: #2

#### サブタスク

- [ ] `internal/auth/provider/oidc.go` 実装
- [ ] OIDC Discovery + JWKS フェッチ
- [ ] ID Token 検証（署名・クレーム）
- [ ] 環境変数追加（`OAUTH_ISSUER_URL`, `OAUTH_AUDIENCE` 等）
- [ ] Auth0 / Keycloak での結合テスト
