# Tasks Archive: v0.4.0 - v0.6.0

`tasks.md` から外した完了済みタスクの archive。v0.3.0 以前の履歴は [`tasks-archive-v0.3.0.md`](tasks-archive-v0.3.0.md) を参照。

このファイルは詳細な変更履歴ではなく、タスク管理上「完了済みとして現行ロードマップから外した issue」の索引である。リリース単位の詳細は [`CHANGELOG.md`](../CHANGELOG.md) / [`CHANGELOG.ja.md`](../CHANGELOG.ja.md) を参照。

## v0.4.0

| Issue / PR | 状態 | 結果 |
|---|---|---|
| [#5](https://github.com/scottlz0310/mcp-gateway/issues/5) | [x] 完了 | `OAUTH_*` 環境変数を導入し、旧 `GITHUB_MCP_*` を deprecate |
| [#70](https://github.com/scottlz0310/mcp-gateway/issues/70) Phase A | [x] 完了 | GitHub OAuth refresh token rotation を gateway provider に実装 |
| [#72](https://github.com/scottlz0310/mcp-gateway/issues/72) Phase B | [x] 完了 | loopback + shared secret の delegated background access PoC を実装 |
| [#77](https://github.com/scottlz0310/mcp-gateway/issues/77) | [x] 完了 | Phase B の rotation correctness gap を修正 |
| [#73](https://github.com/scottlz0310/mcp-gateway/issues/73) Phase C | [x] 完了 | `docs/auth-error-contract.md` を追加し、構造化エラー契約を整理 |

## v0.5.x

| Issue / PR | 状態 | 結果 |
|---|---|---|
| [#82](https://github.com/scottlz0310/mcp-gateway/issues/82) | [x] 完了 | `ROUTE_*` に `upstream_bearer_token_env` を追加 |
| [#86](https://github.com/scottlz0310/mcp-gateway/pull/86) | [x] 完了 | 空または whitespace-only の `ROUTE_*` を skip するよう修正 |
| [#89](https://github.com/scottlz0310/mcp-gateway/issues/89) | [x] 完了 | Codecov step の failure handling を `fail_ci_if_error: false` 側へ整理 |
| [#93](https://github.com/scottlz0310/mcp-gateway/issues/93) | [x] 完了 | `:latest` image tag を release 専用に分離 |
| [#94](https://github.com/scottlz0310/mcp-gateway/pull/94) | [x] 完了 | prerelease tag 運用を `CONTRIBUTING.md` に記載 |

## v0.6.0

| Issue / PR | 状態 | 結果 |
|---|---|---|
| [#92](https://github.com/scottlz0310/mcp-gateway/issues/92) | [x] 完了 | review platform における mcp-gateway の責務境界を `docs/architecture.md` に明文化 |
| [#96](https://github.com/scottlz0310/mcp-gateway/issues/96) | [x] 完了 | docs の旧 `copilot-review-mcp` 参照を `review-raven` 前提へ更新 |
| [#98](https://github.com/scottlz0310/mcp-gateway/pull/98) | [x] 完了 | OIDC Provider 初期実装と OIDC RSA private key 永続化を追加 |
| [#100](https://github.com/scottlz0310/mcp-gateway/issues/100) | [x] 完了 | `redirect_uri` 許可ホストの env / config 設定経路を追加 |
| [#102](https://github.com/scottlz0310/mcp-gateway/issues/102) | [x] 完了 | OAuth audit log / rotation / `GET /internal/v1/auth/failures` を実装 |
| [#104](https://github.com/scottlz0310/mcp-gateway/pull/104) | [x] 完了 | `github-mcp-server` 向け PAT injection 設定を example route に追加 |
| [#105](https://github.com/scottlz0310/mcp-gateway/issues/105) | [x] 完了 | ルーティング先 MCP server の認証切れ調査レポートを追加 |
| [#108](https://github.com/scottlz0310/mcp-gateway/issues/108) | [x] 完了 | proxy 転送前に route prefix を strip する機能を追加 |
| [#111](https://github.com/scottlz0310/mcp-gateway/issues/111) | [x] 完了 | exact-prefix 転送で upstream base path に末尾 slash を付けないよう修正 |
| [#119](https://github.com/scottlz0310/mcp-gateway/issues/119) | [x] 完了 | PR #98 の OIDC Provider 実装状態と agy 残課題を調査 |
| [#120](https://github.com/scottlz0310/mcp-gateway/issues/120) | [x] 完了 | external OIDC IdP provider mode は #126 方針により不要と整理 |
| [#121](https://github.com/scottlz0310/mcp-gateway/issues/121) | [x] 完了 | RFC 8252 custom URL scheme redirect URI の authority form を許可 |
| [#127](https://github.com/scottlz0310/mcp-gateway/issues/127) | [x] 完了 | `OAUTH_PROVIDER=builtin` と gateway-issued RS256 JWT を実装 |
| [#128](https://github.com/scottlz0310/mcp-gateway/issues/128) | [x] 完了 | refresh token rotation と reuse detection を実装 |
| [#129](https://github.com/scottlz0310/mcp-gateway/issues/129) | [x] 完了 | route ごとの `aud` claim 分離を実装 |
| [#130](https://github.com/scottlz0310/mcp-gateway/issues/130) | [x] 完了 | gateway-native Device Authorization Grant を完全実装 |
| [#133](https://github.com/scottlz0310/mcp-gateway/issues/133) | [x] 完了 | revoked refresh token の上書きリスクを SQLite-backed store 移行で解消 |
| [#134](https://github.com/scottlz0310/mcp-gateway/issues/134) | [x] 完了 | RefreshTokenStore を SQLite-backed に移行 |
| [#138](https://github.com/scottlz0310/mcp-gateway/issues/138) | [x] 完了 | GitHub Apps 移行の親 issue を完了 |
| [#139](https://github.com/scottlz0310/mcp-gateway/issues/139) | [x] 完了 | GitHub OAuth Apps から GitHub Apps user-to-server OAuth へ切り替え |
| [#140](https://github.com/scottlz0310/mcp-gateway/issues/140) | [x] 完了 | `ghu_` / `ghr_` token の rotation 互換テストと docs を追加 |
| [#143](https://github.com/scottlz0310/mcp-gateway/issues/143) | [x] 完了 | Device Flow `/callback` 二重 code exchange 問題を修正 |
| [#144](https://github.com/scottlz0310/mcp-gateway/issues/144) | [x] 完了 | 実行時生成ファイルの default path を OS user state dir へ変更 |
| [#145](https://github.com/scottlz0310/mcp-gateway/issues/145) | [x] 完了 | GitHub App 推奨 Permission 設定を README / `.env.example` に追記 |
| [#147](https://github.com/scottlz0310/mcp-gateway/issues/147) | [x] 完了 | default path documentation を実装に同期 |
| [#150](https://github.com/scottlz0310/mcp-gateway/issues/150) | [x] 完了 | `docs/` 配下の主要ドキュメントを日本語化 |

## tasks.md から移動した詳細タスク

以下は旧 `tasks.md` に詳細サブタスクとして残っていたが、いずれも完了済みのため archive 扱いにした。

### [#140](https://github.com/scottlz0310/mcp-gateway/issues/140) GitHub Apps トークン有効期限対応

- [x] `tryGitHubRotation` が `ghu_` / `ghr_` トークンで動作することを確認
- [x] `internal/auth/provider/github_test.go` に `ghu_` access token / `ghr_` refresh token のテストケースを追加
- [x] `internal/auth/delegated_access_test.go` に `TestEnsureFreshAccessTokenForSubject_GhuTokenRotation` を追加
- [x] `docs/configuration.md` に GitHub App 側の "Expire user authorization tokens" 有効化手順を追加
- [x] `README.md` / `README.ja.md` / `CHANGELOG.md` / `CHANGELOG.ja.md` を更新

### [#139](https://github.com/scottlz0310/mcp-gateway/issues/139) GitHub Apps への切り替え本体

- [x] `ghu_` token 受け入れ確認
- [x] GitHub App 前提のコメント・エラーメッセージ・テスト fixture へ更新
- [x] README / README.ja.md / docs/configuration.md を GitHub App 作成手順へ更新
- [x] CHANGELOG / tasks を更新

### [#105](https://github.com/scottlz0310/mcp-gateway/issues/105) 認証切れ調査

- [x] `auth-audit.jsonl` と設定値の相関を確認
- [x] `docs/spike-105-auth-issue-investigation.md` を作成
- [x] 対策タスクを別 repo 管轄として整理

### [#104](https://github.com/scottlz0310/mcp-gateway/pull/104) github-mcp-server proxy 認証失敗修正

- [x] example compose に `GITHUB_PERSONAL_ACCESS_TOKEN` を追加
- [x] `ROUTE_GITHUB` に `upstream_bearer_token_env=GITHUB_PERSONAL_ACCESS_TOKEN` を追加
- [x] CHANGELOG / tasks を更新

### [#102](https://github.com/scottlz0310/mcp-gateway/issues/102) OAuth 監査ログ

- [x] `internal/authaudit` に OS 別 external path と Git worktree 拒否を実装
- [x] JSON Lines / size / generation / age rotation を実装
- [x] OAuth error の型付き抽出と redaction を追加
- [x] authorize / callback / token exchange / identity resolution / refresh / rotation を監査
- [x] `GET /internal/v1/auth/failures` を追加
- [x] README / docs / CHANGELOG を更新

### [#100](https://github.com/scottlz0310/mcp-gateway/issues/100) redirect_uri 許可ホスト設定

- [x] `GatewayConfig.AllowedRedirectHosts` を追加
- [x] `MCP_GATEWAY_ALLOWED_REDIRECT_HOSTS` と config fallback を追加
- [x] default allowlist に `antigravity.google` を追加
- [x] tests / docs / CHANGELOG を更新

### [#70](https://github.com/scottlz0310/mcp-gateway/issues/70) Auth Lifecycle Mismatch 対応

- [x] Phase A: GitHub OAuth refresh token rotation を実装
- [x] Phase B: delegated background access PoC を実装
- [x] Phase B follow-up: rotation correctness gap を修正
- [x] Phase C: auth error contract docs を整理

## 現行 tasks.md に残すもの（2026-06-18 時点）

- `#122` / `#123` / `#125` / `#6`: OIDC Authorization Server 完成に必要な未実装 issue
- `#84` / `#113` - `#118`: upstream OAuth delegation の未実装 chain
- `#65`: Renovate Dependency Dashboard
