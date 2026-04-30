# Tasks

`mcp-gateway` の継続的なタスク管理ファイル。各 issue の状態とサブタスク、依存関係を記録する。

## 凡例

- `[ ]` 未着手
- `[~]` 進行中
- `[x]` 完了
- `[-]` 保留 / 別 issue へ移管

---

## 推奨消化順（2026-04-30 更新）

### Phase 1 — 今すぐ着手（コード変更不要）

| 優先 | ISSUE | 理由 |
|---|---|---|
| 1 | **mcp-gateway #19** Compose ルーティング | ✅ 完了（PR #20 マージ済み） |
| 2 | **mcp-gateway #18** Copilot API 調査 | ✅ 完了（PR #21 マージ済み） |

### Phase 2 — #19 動作確認後

| 優先 | ISSUE | 理由 |
|---|---|---|
| 3 | **mcp-gateway #16** Device Flow 直列化 | ✅ 完了（PR #31 マージ済み） |
| 4 | **copilot-review-mcp #12** AUTH_MODE=gateway | #19 で二重検証が問題になる場合に対処。変更量は小 |
| 5 | **mcp-gateway #15** ユーザーホワイトリスト | 運用上の需要が出たタイミングで |

### Phase 3 — インフラ整備（長期）

| 優先 | ISSUE | 理由 |
|---|---|---|
| 6 | **mcp-gateway #11** Config Persistence | 大きめ。Phase 2 が安定してから |
| 7 | **mcp-gateway #12** Setup Wizard | #11 完了が前提 |

### 保留維持

| ISSUE | 保留理由 |
|---|---|
| **#6** 汎用 OIDC | #18 結果次第で再評価 |
| **#5** env var 移行 | 追加プロバイダ確定まで YAGNI |
| **#4** fly.io OAuth | fly.io と直接調整が必要 |
| **#3** fly.io 調査 | 調査完了済み・保留 |

---

## Issue 一覧

---

### Phase 1

---

### [#19 feat: copilot-review-mcp を mcp-gateway 経由でルーティングする（Compose 設定 + 動作検証）](https://github.com/scottlz0310/mcp-gateway/issues/19)

**状態**: ✅ 完了（2026-04-28、PR #20 マージ済み）
**依存**: なし

copilot-review-mcp 側のコード変更ゼロで、`ROUTE_COPILOT_REVIEW=/mcp/copilot-review|http://copilot-review-mcp:8083` だけで動作する可能性が高い（Go ServeMux の subtree マッチングによる）。

#### サブタスク

- [x] mcp-docker 側の Compose 設定変更案作成（`ROUTE_COPILOT_REVIEW` 追加）
- [x] MCP クライアント（VS Code / Claude Desktop）での接続テスト
- [x] トークン二重検証の影響測定（キャッシュ効果の確認）
- [x] copilot-review-mcp への直接接続が壊れないことの確認（後方互換チェック）
- [x] README / CHANGELOG への反映

---

### [#18 spike: https://api.githubcopilot.com/mcp/ を upstream とした際の認証互換性調査](https://github.com/scottlz0310/mcp-gateway/issues/18)

**状態**: ✅ 完了（2026-04-28、PR #21 マージ済み）
**依存**: なし
**調査結果ドキュメント**: [`docs/spike-18-copilot-api-auth.md`](docs/spike-18-copilot-api-auth.md)

#### 主な発見

- `gho_` トークン（標準 GitHub OAuth）で MCP initialize 200 OK を確認
- upstream URL は `https://api.githubcopilot.com`（パスなし）と設定すること（`/mcp/` を含めると二重化）
- 複数ルートとの共存: `ROUTE_COPILOT=/mcp|https://api.githubcopilot.com` + `ROUTE_COPILOT_REVIEW=/mcp/copilot-review|http://copilot-review-mcp:8083`
- `WWW-Authenticate` ヘッダは、今回検証したクライアント/設定では書き換え不要だったが、401 時の `resource_metadata` は upstream URL を指すため将来的な書き換え検討余地あり
- copilot-cli の直接接続失敗はトークン形式の問題ではなく、OAuth App スコープ or MCP client 設定の問題

#### サブタスク

- [x] `https://api.githubcopilot.com/.well-known/oauth-authorization-server` の確認
- [x] `gho_...` トークンでの直接アクセステスト（`curl -H "Authorization: Bearer gho_..."`)
- [x] 必要なトークン形式・OAuth スコープの特定
- [x] per-upstream 認証設定の必要性評価
- [x] 調査結果を `docs/spike-18-copilot-api-auth.md` に記録

---

### Phase 2

---

### [#16 feat(auth): Device Flow の同時ポーリングを per-device で直列化して GitHub レート制限を回避](https://github.com/scottlz0310/mcp-gateway/issues/16)

**状態**: ✅ 完了（2026-04-30、PR #31 マージ済み）
**依存**: なし

同一 `device_code` への並列リクエストが GitHub を同時 polling → `slow_down` / レート制限を誘発する問題。

#### サブタスク

- [x] per-device mutex（または singleflight）の実装 → `AcquireDevicePolling` / `ReleaseDevicePolling`
- [x] 既存 `AuthorizeAndConsumeDevice` との整合性確認
- [x] テスト追加（並列リクエストのシミュレーション）
- [x] PR #31 Copilot レビュー対応・スレッドクローズ

---

#### [copilot-review-mcp #12 feat: AUTH_MODE=gateway 対応（mcp-gateway 経由モード・二重検証の排除）](https://github.com/scottlz0310/copilot-review-mcp/issues/12)

**状態**: 未着手（#19 動作確認後に着手）
**リポジトリ**: `scottlz0310/copilot-review-mcp`
**依存**: mcp-gateway #19

`AUTH_MODE=gateway` 環境変数で `X-Authenticated-User` ヘッダーを信頼するモードを追加。`GITHUB_CLIENT_ID/SECRET` を任意化。デフォルト（`standalone`）は後方互換維持。

#### サブタスク

- [ ] `internal/middleware/auth.go` に `AuthMode` 分岐追加（+20〜30行）
- [ ] `cmd/server/main.go` の `AUTH_MODE` 読み込みと条件分岐（+20行）
- [ ] `AUTH_MODE=gateway` 時の `GITHUB_CLIENT_ID/SECRET` を optional に変更
- [ ] テスト追加（gateway モード単体テスト）
- [ ] README / CHANGELOG 更新

---

### [#15 feat: ホワイトリストによるアクセス制限（認証済みユーザーのフィルタリング）](https://github.com/scottlz0310/mcp-gateway/issues/15)

**状態**: 保留
**依存**: なし（独立着手可能）

> **保留理由（2026-04-30）**: env var 設計か YAML config 設計かで方針が未確定。
> #11（Config Persistence）の方向性が固まってから実装する。Docker 運用継続中は緊急度低。

#### サブタスク

- [ ] 設定方式の決定（env var / YAML config）
- [ ] middleware でのフィルタリング実装
- [ ] テスト追加
- [ ] README 更新

---

### Phase 3

---

### [#11 feat: Config Persistence Layer（env vars → YAML/SQLite 設定ファイル）](https://github.com/scottlz0310/mcp-gateway/issues/11)

**状態**: 保留
**依存**: なし（独立着手可能）

> **保留理由（2026-04-30）**: Docker 運用継続中は env var で十分機能しており YAGNI。
> ホスティング移行やマルチユーザー運用が現実になったタイミングで再評価する。
> SQLite・管理画面・Setup Wizard はそれ以降に検討（過剰設計を避ける）。

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

---

### 保留中

---

### [#6 feat: 汎用 OIDC（OpenID Connect）プロバイダサポート](https://github.com/scottlz0310/mcp-gateway/issues/6)

**状態**: 保留（2026-04-27）
**依存**: #2
**保留理由**: Entra ID は DCR 未サポートで MCP OAuth 2.1 仕様と不適合。対象 MCP サーバーが具体的に決まるまで見送り（YAGNI）。**#18 の結果次第で再評価**。

#### サブタスク

- [-] `internal/auth/provider/oidc.go` 実装（保留）
- [-] OIDC Discovery + JWKS フェッチ（保留）
- [-] ID Token 検証（署名・クレーム）（保留）
- [-] 環境変数追加（`OAUTH_ISSUER_URL`, `OAUTH_AUDIENCE` 等）（保留）
- [-] Auth0 / Keycloak での結合テスト（保留）

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

### 完了 / クローズ

---

### [#2 refactor: OAuth プロバイダ抽象化（Provider インターフェース導入・GitHub 実装の移植）](https://github.com/scottlz0310/mcp-gateway/issues/2)

**状態**: ✅ 完了（2026-04-28、PR #7 マージ済み）
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

### [#8 feat: Google OAuth 2.0 プロバイダ実装](https://github.com/scottlz0310/mcp-gateway/issues/8)

**状態**: クローズ（2026-04-27・YAGNI）
**理由**: Google 公式 MCP サーバーは OAuth + Streamable HTTP を既に内包。対象 MCP サーバーが具体的に決まるまで見送り。

---

### [#22 feat: per-route auth bypass via ROUTE_<NAME>=<prefix>|<upstream>|auth=none](https://github.com/scottlz0310/mcp-gateway/issues/22)

**状態**: ✅ 完了（2026-04-28、PR #23 マージ済み）
**依存**: なし

`ROUTE_<NAME>` 環境変数の第3セグメントに `auth=none` を指定すると、そのルートで認証ミドルウェアをスキップする。Copilot API の like public upstream に使用。

---

### [#24 feat: OAuth トークン/セッション状態の永続化（再認証スキップ）](https://github.com/scottlz0310/mcp-gateway/issues/24)

**状態**: ✅ 完了（2026-04-28、PR #25 マージ済み）
**依存**: なし

`MCP_GATEWAY_TOKEN_STORE_PATH` 環境変数でJSON ファイルベースのトークンストアを有効化。ゲートウェイ再起動後もMCPクライアントの再認証不要。

---

### [#26 fix: リフレッシュトークン切れによる「session not found」エラー調査と対処](https://github.com/scottlz0310/mcp-gateway/issues/26)

**状態**: ✅ 完了（2026-04-30、PR #27 マージ済み）
**依存**: なし

RFC 6749 §6 の `grant_type=refresh_token` を実装。アクセストークン期限切れ時にリフレッシュトークンで再発行できるようにした（ローテーション付き・並列リクエスト対応）。

---

### [#28 fix: Dockerfile `/data` ディレクトリを nonroot 所有で作成](https://github.com/scottlz0310/mcp-gateway/issues/28)

**状態**: ✅ 完了（2026-04-30、PR #29 マージ済み）
**依存**: なし

builder ステージで `/data` を `nonroot:nonroot` 所有で作成し、init コンテナなしで永続ストアが書き込み可能になった。

---

### [#10 spike: Device Authorization Grant を gateway レイヤーで実装する可能性調査](https://github.com/scottlz0310/mcp-gateway/issues/10)

**状態**: ✅ 完了（2026-04-28、PR #14 マージ済み）
**依存**: #2（完了済み）

`POST /device_authorization` + `/token` の device_code grant を実装済み。アーキテクチャは **gateway が Device Grant を実行する**方式（MCP Client → mcp-gateway → GitHub）。

#### サブタスク

- [x] GitHub Device Grant エンドポイント（`client_secret` 要否）の確認
- [x] gateway 内 Device Grant フロー設計（`POST /device_authorization`・`POST /token` `grant_type=urn:ietf:params:oauth:grant-type:device_code`）
- [x] MCP Authorization Server Metadata への `device_authorization_endpoint` 追加
- [x] 既存 Authorization Code Flow との共存設計・実装
