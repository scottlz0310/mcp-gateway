# Tasks

`mcp-gateway` の継続的なタスク管理ファイル。各 issue の状態とサブタスク、依存関係を記録する。

過去のリリース履歴（v0.1.0 〜 v0.3.0）は [`docs/tasks-archive-v0.3.0.md`](docs/tasks-archive-v0.3.0.md) を参照。

## 凡例

- `[ ]` 未着手
- `[~]` 進行中
- `[x]` 完了
- `[-]` 保留 / 別 issue へ移管

---

## Issue #102 — OAuth 認証監査ログの永続化・ローテーション・診断機能

**目的**: OAuth 認証フローの成否と失敗原因を、リポジトリ外の機械可読な監査ログと internal API から事後解析可能にする。

### サブタスク

- [x] `internal/authaudit` に OS 別の外部保存 path 解決と Git worktree 配下拒否を実装
- [x] JSON Lines、10 MiB、5世代、30日保持のローテーションを実装
- [x] provider の OAuth エラーを型付き化し、`oauth_error` と HTTP status を安全に抽出
- [x] authorize / callback / token exchange / identity resolution / refresh / rotation の監査イベントを追加
- [x] 直近100件の失敗を保持し、`GET /internal/v1/auth/failures` から参照可能にする
- [x] 公式 container image の `XDG_STATE_HOME` を `/data` に設定し、既定 path を `/data/mcp-gateway/logs/auth-audit.jsonl` に解決
- [x] 機密情報除外、ローテーション境界、保持数・日数、並行書き込み、診断 API のテストを追加
- [x] `README.md` / `README.ja.md` / `docs/configuration.md` / `docs/operations.md` を更新
- [x] `CHANGELOG.md` / `CHANGELOG.ja.md` の `Unreleased` を更新

---

## Issue #100 — redirect_uri 許可ホストに設定経路がなく agy 認証が失敗する

**目的**: agy（Antigravity）からの OAuth 認証が許可リスト制限で失敗する問題を解消するため、ホスト許可リストの設定手段（環境変数および config.yaml）を追加し、デフォルト許可ホストに `antigravity.google` を加える。

### サブタスク

- [x] `internal/config/config.go` の `GatewayConfig` に `AllowedRedirectHosts` フィールドを追加し、`config.yaml` から設定可能にする
- [x] `cmd/server/main.go` にて環境変数 `MCP_GATEWAY_ALLOWED_REDIRECT_HOSTS`（カンマ区切り）の読み込み経路と、`config.yaml` からのフォールバックを設定
- [x] `internal/auth/handler.go` のデフォルト `AllowedRedirectHosts` に `antigravity.google` を追加
- [x] ユニットテストを追加し、デフォルト動作とカスタム設定時の挙動を検証
- [x] `docs/configuration.md` に設定項目について追記
- [x] `CHANGELOG.md` / `CHANGELOG.ja.md` の `Unreleased` セクションに変更内容を追記

---

## アクティブフェーズ: Issue #70 — Auth Lifecycle Mismatch 対応

### 背景

[Issue #70](https://github.com/scottlz0310/mcp-gateway/issues/70) の spike 調査により、`mcp-gateway` ↔ `copilot-review-mcp` 間で次の構造が確認された:

- 当初: ゲートウェイは Bearer トークン（`gho_*`）を upstream にパススルーするだけで、proxying 経路でのトークン refresh は未実装だった（`internal/proxy/handler.go` の `Rewrite` callback、`internal/auth/handler.go` の `Handler.ValidateToken`）。**Phase A (本ブランチ) で `Handler.ValidateToken` 側に rotation 統合が完了している（gate: `gateway.github_refresh_enabled`）。**
- `copilot-review-mcp` 側は watch 開始時の token を `oauth2.StaticTokenSource` でスナップショットし、最大 2 時間のバックグラウンドポーリングを行う（refresh 不可）
- 短命トークン（GitHub App installation token 等、有効期限 ≦ 2 時間）を扱う構成では watch 途中で確実に失効する
- 現行設計でも `FailureReasonAuthExpired` により AI エージェントへの構造化通知は機能しているため、緊急の暫定対処は不要

調査詳細は Issue #70 のコメント参照:
- [gateway 側調査](https://github.com/scottlz0310/mcp-gateway/issues/70#issuecomment-4423105027)
- [upstream 側調査](https://github.com/scottlz0310/mcp-gateway/issues/70#issuecomment-4423300774) / [追加 deep dive](https://github.com/scottlz0310/mcp-gateway/issues/70#issuecomment-4423383186)
- [統合まとめと方針](https://github.com/scottlz0310/mcp-gateway/issues/70#issuecomment-4423496131)

### 採用方針

- 現行の非同期 watch 設計（`copilot-review-mcp` 側 Option B = token snapshot）は維持する
- Option A（request-scoped 化）への回帰は採らない（`wait_for_copilot_review` で legacy fallback として残し、新規 work はしない）
- 根本対策は gateway 側を主軸に、フェーズ分けで進める

---

## Phase A: GitHub OAuth refresh token rotation を gateway provider に実装（短期・low risk）

**目的**: GitHub OAuth App で expiring tokens が有効化されているデプロイにおいて、access token の期限切れをゲートウェイ層で自動回復させる。これにより `copilot-review-mcp` の watch goroutine がスナップショットしたトークンが切れる前に、後続リクエスト経由で fresh token に置き換わるシナリオを増やす。

**Issue**: 新規作成予定（Phase A の専用 issue を切る）

### サブタスク

- [x] `internal/auth/provider/github.go` に refresh token rotation API（`POST https://github.com/login/oauth/access_token` `grant_type=refresh_token`）を追加
- [x] `internal/auth/tokenstore.go` の `TokenRecord` に GitHub 側 refresh token と GitHub access token の有効期限を保存できるよう拡張（既存の gateway-issued refresh token とは別フィールド）
- [x] `internal/auth/handler.go:ValidateToken` で「キャッシュ hit だが GitHub access token の有効期限が近い」場合に rotation を試みるパスを追加
- [x] rotation 失敗時の挙動: cache を維持し、ログに `rotation_failed` を残して既存の 401 経路に委譲（後段で upstream が 401 を返した場合に `invalid_token` で再認証を促す）
- [x] `cfg.GitHubRefreshEnabled` で機能 gate（OAuth App が non-expiring 構成の場合は no-op）
- [x] 既存 `Handler` テストへ rotation 成功 / 失敗 / 期限ギリギリ / gate off / metadata 欠落 / 空 access_token / ErrRefreshNotSupported の 7 ケースをテーブル駆動で追加
- [x] `docs/configuration.md` に rotation 設定とトラブルシュートを追記
- [x] `CHANGELOG.md` / `CHANGELOG.ja.md` の Unreleased セクションに Phase A の追加・変更を記載

### 受け入れ基準

- [x] expiring tokens 有効な OAuth App 構成下で、access token が期限切れ直前のリクエストを送ったときにキャッシュが silently rotate される
- [x] rotation 後の新 access token が `proxy.NewHandler` 経由で upstream に届く（`middleware.Auth` が context の bearer を差し替える）
- [x] rotation 失敗時にクライアントは `invalid_token` を受け取り、`WWW-Authenticate` から再認証フローに進める（upstream 401 経由）
- [x] 既存テストの後方互換 (non-expiring 構成) が崩れない

### 既知の限界

- `copilot-review-mcp` の watch goroutine は依然 snapshot を保持するため、**watch 実行中の差し替えは行われない**。Phase A は「次に gateway 経由で watch を再起動するリクエスト」のたびに fresh token を流せるようにするだけ。watch 中の自動更新は Phase B で扱う。

---

## Phase B: Delegated background access（完了）

**目的**: upstream MCP server（`copilot-review-mcp` 等）が background workflow から「現在の有効 token を取り直す」ことを許す内部 API をゲートウェイに追加し、Option C（gateway-managed delegated access）の小さい実装を検証する。

**Issue**: [#72](https://github.com/scottlz0310/mcp-gateway/issues/72)（PoC 実装、PR #76 でマージ済み）、[#77](https://github.com/scottlz0310/mcp-gateway/issues/77)（rotation 正確性ギャップ修正）

### サブタスク

- [x] 設計ドキュメント `docs/spike-72-delegated-background-access.md` を作成
  - エンドポイント: `POST /internal/v1/whoami`（loopback bind + shared secret）
  - trust boundary: loopback(127.0.0.1) + `MCP_GATEWAY_INTERNAL_SECRET`（HMAC-safe ConstantTimeCompare）
  - upstream 側がトークンを保存しない設計を維持する API 形状
- [x] PoC ブランチで `/internal/v1/whoami` ハンドラ実装（loopback bind 限定）— `internal/internalapi/`
- [x] `EnsureFreshAccessTokenForSubject` を `Handler` に実装（subject ベースの delegated token lookup + 自動 rotation）
- [x] `LatestBySubject` を `Store` に実装（subject index による token ranking）
- [x] `copilot-review-mcp` 側の client 実装 draft 提案（別リポジトリ issue として連動）
- [x] **Gap 2 修正** (#77): 永続的 rotation 失敗後のレニエントブランチが dead bearer を返す問題を修正
  - `Store.MarkRotationPermanentlyFailed` / `IsRotationPermanentlyFailed` を追加
  - `runGitHubRotation` の永続失敗パスで `MarkRotationPermanentlyFailed` を呼び出す
  - レニエントブランチで `IsRotationPermanentlyFailed` チェックを追加
- [x] **Gap 3 修正** (#77): `LatestBySubject` の同一 `ProviderAccessExpiry` 時の tie-break 修正
  - `.Equal()` 条件を追加し、後から登録されたエントリ（新しい rotated token）を優先
- [x] Phase B 本採用評価レポート `docs/phase-b-adoption-report.md` 作成
- [x] テスト追加: Gap 2 (`TestEnsureFreshAccessTokenForSubject_PermanentFailureLenientBranchReturnsError`)、Gap 3 (`TestLatestBySubjectTieBreaksOnInsertionOrder`)

### 受け入れ基準（PoC ゲート）

- [x] ローカル composing 環境で gateway と upstream MCP が trust boundary 越しに通信できることを確認
- [x] セキュリティレビュー（loopback 限定、認証 secret の取り扱い）が完了している
- [x] Option C を採るか、より軽量な手段に切り戻すかの判断材料が docs として残る（`docs/phase-b-adoption-report.md` 参照）

### 既知の限界（#77 修正後残存分）

- subject index はインメモリのみ: gateway 再起動後、再認証まで delegated アクセス不可
- `rotationFailed` フラグ永続化（Issue #77 Thread 1 対応済み）: `MarkRotationPermanentlyFailed` が token store に `RotationPermanentlyFailed` フラグを永続化（file-backed store はディスクへフラッシュ）し、subject index からも即時削除する。`ValidateToken` は再起動後も `RefreshSubjectIndex` をスキップするため、dead bearer が subject index に再挿入されることはない。`EnsureFreshAccessTokenForSubject` は `ErrSubjectNotFound` を返す
- スコープは gateway 全体設定: トークンごとの fine-grained scope は将来課題
- Unix socket / mTLS による multi-host 構成は未実装（同一ホスト構成限定）

---

## Phase C: 構造化エラー契約の整理（中期、Phase B と並走可）

**目的**: `AUTH_CONTEXT_UNAVAILABLE` を導入するか否かを決め、ゲートウェイ→upstream・upstream→クライアントの間のエラーコード契約を整理する。

**Issue**: 新規作成予定（軽量 issue、docs 主体）

### サブタスク

- [ ] `docs/auth-error-contract.md` を新設し、`invalid_request` / `invalid_token` / `upstream_error` の境界条件を明文化
- [ ] Phase B 採用時のみ `AUTH_CONTEXT_UNAVAILABLE` を追加候補として記載（Phase B 非採用なら本項目はクローズ）
- [ ] `copilot-review-mcp` 側 `FailureReasonAuthExpired` 等とのマッピング表を整備

### 受け入れ基準

- `WWW-Authenticate` の `error=` 値と JSON body の `error` 値が docs と一致する
- 既存テスト（`internal/middleware/auth_test.go`）でエラーコードの後方互換が保証される

---

## スコープ外（他リポジトリ管轄）

これらは `copilot-review-mcp` 側 issue として扱い、本リポジトリの tasks.md では追跡しない。

- [`copilot-review-mcp`] `InvalidateToken: nil` の活性化（Phase B の API が用意できた後に対応）
- [`copilot-review-mcp`] `FailureReasonAuthExpired` の recovery hint 強化（watch token snapshot expired 等）
- [`copilot-review-mcp`] 起動時 STALE 化（既に `MarkActiveReviewWatchesStale` で実装済み、確認のみ）

---

## 実装着手順（推奨）

1. **Phase A**: 本 PR (#71) で実装＋docs＋テストまで揃ったので、レビュー反映完了後に main へマージ
2. Phase A マージ後、Phase B の spike issue を切り、設計ドキュメントを先に書く
3. Phase B の PoC で trust boundary が固まったら Phase C のエラー契約 docs を仕上げる

---

## 直近の未消化 issue（参考）

Issue #70 以外の継続タスクは過去アーカイブ（[`docs/tasks-archive-v0.3.0.md`](docs/tasks-archive-v0.3.0.md)）を参照。新規追加分は本ファイル上部のフェーズ表に随時追記する。
