# Phase B — 委任バックグラウンドアクセス: PoC から本番移行採用レポート

> **判定: GO — Phase B 実装を現状のまま採用する（記載の制限事項あり）。**

---

## 1. 背景

Issue #70 で `copilot-review-mcp` がウォッチ開始時に GitHub OAuth Bearer をスナップショットし、最大 2 時間のバックグラウンドポーリング中それを保持することが特定されました。短命のトークン（GitHub App インストールトークン・期限切れ OAuth App トークン）はウォッチ中に期限切れになり `FailureReasonAuthExpired` を返します。Phase A（PR #71）はインバウンドリクエストでのゲートウェイ側ローテーションを追加しましたが、既に実行中の watch goroutine に到達できませんでした。Phase B はプル型の内部 API を追加し、upstream MCP サーバーが必要な時にゲートウェイから新鮮なトークンを要求できるようにします。認証情報自体を保存する必要はありません。

---

## 2. Phase B で実装した内容（PR #76 + Issue #77）

### 2.1 内部 API（`/internal/v1/whoami`）

| 属性 | 値 |
|------|---|
| トランスポート | HTTP、ループバックのみ（`127.0.0.1`、`gateway.internal_addr` で設定可能） |
| 認証 | `MCP_GATEWAY_INTERNAL_SECRET` 共有シークレット、`Authorization: Bearer <secret>` |
| メソッド / パス | `POST /internal/v1/whoami` |
| リクエストボディ | `{"subject": "<github_login>"}` |
| レスポンス | `{"access_token": "...", "provider_access_expiry": "...", "scopes": "..."}` |
| 実装 | `internal/internalapi/` パッケージ（公開ゲートウェイ mux から分離） |

共有シークレットはタイミング攻撃を防ぐため `subtle.ConstantTimeCompare` で比較されます。サーバーはループバックインターフェースのみにバインドされるため、同一ホストデプロイには TLS は不要です。

### 2.2 `EnsureFreshAccessTokenForSubject`（ハンドラーレイヤー）

委任アクセスの中核プリミティブ。`/internal/v1/whoami` ハンドラーから呼び出されます:

1. `LatestBySubject(subject)` — インメモリ subject インデックスで指定された GitHub ログインの最も新しくローテーションされたトークンを検索。
2. キャッシュされた有効期限がリードウィンドウ内にあり、リフレッシュトークンが利用可能な場合は `runGitHubRotation` をトリガー（`singleflight` で重複排除）。
3. 結果の `DelegatedAccessResult{AccessToken, ProviderAccessExpiry, Scopes}` または型付きエラー（`ErrSubjectNotFound`、`ErrRotationFailed`）を返す。

### 2.3 Subject インデックス（`Store.subjectIndex`）

GitHub `login` → `[]subjectIndexEntry` のインメモリマップ。トークンがキャッシュされるたび（`CacheToken`）またはローテーションが完了するたび（`RecordProviderRefresh`）に更新されます。subject のすべてのトークンを O(n) スキャンして最適なものを選択できます。

---

## 3. 修正された正確性ギャップ（Issue #77）

PR #76 の Copilot レビューサイクルで 3 つのギャップが特定されました:

### ギャップ 1 — 同時二重ローテーション → `noOp`（✅ PR #76 で修正済み）

`singleflight` グループが同じ生トークンに対する同時 `EnsureFreshAccessTokenForSubject` 呼び出しを重複排除します。複数の goroutine が競合する場合、リーダーがローテーションを実行し、フォロワーは更新されたレコードを観察して `rotationResult{noOp: true}` を返します（新しい有効期限がすでにリードウィンドウ外にあるため）。コード変更は不要でした。

### ギャップ 2 — 永続的なローテーション失敗 → 寛大なブランチ経由の死んだ Bearer（✅ Issue #77 で修正済み）

**根本原因**: `runGitHubRotation` が永続的な失敗（`bad_refresh_token`・失効した認証情報）時に `ClearProviderRefresh(token)` を呼び出していました。これにより `ProviderRefreshToken` と `ProviderAccessExpiry` がゼロになりました。次の `EnsureFreshAccessTokenForSubject` 呼び出しはトークンを寛大なブランチ（リフレッシュメタデータなし → ローテーション試行なし）で見つけ、死んだ Bearer を HTTP 200 で返しました。

**修正**:
- `rotationFailed map[string]struct{}`（`tokenKey` SHA-256 ハッシュをキーとする）を `Store` に追加。
- `MarkRotationPermanentlyFailed(token)` が `ClearProviderRefresh` を呼び出し**かつ**フラグを設定。
- `IsRotationPermanentlyFailed(token) bool` がフラグを公開。
- `runGitHubRotation` が永続的な失敗（非 upstream エラー・空のアクセストークン）時に `MarkRotationPermanentlyFailed` を呼び出すようになりました。`ErrRefreshNotSupported` は `ClearProviderRefresh` のみを呼び出します（クラシック PAT は失敗ではなく、単にローテーション不可能なため）。
- `EnsureFreshAccessTokenForSubject` の寛大なブランチがトークンを返す前に `IsRotationPermanentlyFailed` を確認し、代わりに `ErrRotationFailed` を返します。

**以前は注意事項だったが今は解決済み**: `rotationFailed` はインメモリのみでした。ゲートウェイ再起動後にフラグが存在せず、ファイルバックのストアにトークンが残っていた場合、`ValidateToken` は次のキャッシュヒット時に `RefreshSubjectIndex` を呼び出し、subject インデックスを再シードしていました。寛大なブランチはフラグを再設定せずに死んだ Bearer を返していました。

**修正（Issue #77、スレッド 1 への対応）**: `MarkRotationPermanentlyFailed` が以下を実行するようになりました:
1. トークンストアエントリーに `RotationPermanentlyFailed` フラグを永続化（ファイルバックストアではディスクにフラッシュ）。
2. `removeSubjectIndexEntry` を介して即座にトークンを subject インデックスから削除。
3. 同一プロセス内での二重チェックのためにインメモリの `rotationFailed` フラグを設定。

`ValidateToken` が `RotationPermanentlyFailed=true` のレコードに対して `RefreshSubjectIndex` をスキップするようになりました。ゲートウェイ再起動後:
- `ValidateToken("at")` → フラグが設定されたレコードを発見 → subject インデックスは再シードされない。
- `EnsureFreshAccessTokenForSubject` → `LatestBySubject` が `ok=false` を返す → `ErrSubjectNotFound`。クライアントは再認証が必要。死んだ Bearer は返されない。

### ギャップ 3 — 等しい有効期限での `LatestBySubject` タイブレーク（✅ Issue #77 で修正済み）

**根本原因**: `runGitHubRotation` が `persistProviderRefresh` を介して同じ `newAccessExpiry` を新しいトークンと古いトークンの両方に書き込んでいました。両方の subject インデックスエントリーが同一の `ProviderAccessExpiry` を持つことになりました。元の厳密な `.After()` 条件は*最初に見つかった*エントリー（スライスに先に追加された古いトークン）を保持していました。

**修正**: ランキング条件を以下に変更:
```go
!foundRotatable ||
rec.ProviderAccessExpiry.After(bestRec.ProviderAccessExpiry) ||
(foundRotatable && rec.ProviderAccessExpiry.Equal(bestRec.ProviderAccessExpiry))
```
前向き反復 + 「等しい場合は更新」→ 最後に追加されたエントリー（新しいトークン）がタイを制します。新しい構造体フィールドは不要でした。

---

## 4. セキュリティモデル評価

| 特性 | 評価 |
|------|------|
| **ネットワーク露出** | ループバックのみ。外部ネットワークから到達不可能。✅ |
| **認証** | 共有シークレット、定数時間比較、`Authorization: Bearer`。同一ホスト IPC には適切。✅ |
| **シークレット保管** | env 変数（`MCP_GATEWAY_INTERNAL_SECRET`）。標準的な 12-factor の実践。✅ |
| **転送中のトークン** | 平文ループバック（127.0.0.1）。同一ホストには許容範囲。ループバックトラフィックは他のホストから観察不能。✅ |
| **保存中のトークン** | Bearer トークンは委任アクセスパスでディスクに書き込まれない。インメモリのみ。✅ |
| **Subject スプーフィング** | 同一ホスト上でシークレットを知っているプロセスはキャッシュされた任意の subject のトークンを要求できる。信頼された同一配置 MCP サーバーには許容範囲。マルチテナント環境には不適切。⚠️ |
| **シークレットローテーション** | ゲートウェイの再起動が必要。シングルバイナリデプロイでは運用オーバーヘッドは低い。✅ |
| **マルチホスト / コンテナ分離** | 非対応。ゲートウェイと MCP サーバーが別々のコンテナで実行される場合、追加のネットワーク設定なし（host-network モード・mTLS 等）ではループバックアプローチが機能しない。⚠️ |

**総合**: セキュリティモデルは同一ホストデプロイ（ベアメタル・シングル Docker ホスト・`network_mode: host` compose）に適切です。マルチホストまたは Kubernetes デプロイでは内部 API に Unix ソケットまたは mTLS が必要です。これは将来のフェーズに延期されています。

---

## 5. 残存する既知の制限事項

| # | 制限事項 | 影響 | 緩和策 / 将来 |
|---|---------|------|-------------|
| L1 | Subject インデックスはインメモリのみ | 再起動後、subject が公開ゲートウェイ経由で再認証するまで委任アクセスが `ErrSubjectNotFound` を返す | ゲートウェイ再起動後にユーザーが再認証する必要がある（現在の動作と同じ） |
| L2 | `RotationPermanentlyFailed` フラグの永続化にはファイルバックストアが必要 | インメモリのみモードでは、再起動後にフラグが再設定される前に 1 回余分なローテーション試行が行われる | 永続的なフラグには `token_store_path`（ファイルバック）を使用する。永続モードでは、`ValidateToken` が再起動後に `RefreshSubjectIndex` をスキップ → `ErrSubjectNotFound` が返される |
| L3 | スコープはゲートウェイ全体（`gateway.github_scopes`） | トークンごとまたは subject ごとのスコープサブセットを付与できない | 細かいスコープは延期 |
| L4 | GitHub が常に `expires_in` を送信するわけではない | GitHub がフィールドを省略した場合、`ProviderAccessExpiry` がゼロになる可能性がある | ローテーションがリードウィンドウベースのヒューリスティックにフォールバック。動作は Phase A から変わらない |
| L5 | マルチホストデプロイ非対応 | ループバックのみバインド。コンテナ分離により内部 API がブロックされる可能性がある | Unix ソケットまたは mTLS サポートは延期 |
| L6 | クラシック PAT トークンはローテーションしない | `ErrRefreshNotSupported` → `ClearProviderRefresh`。PAT は使用可能だが有効期限不明 | 許容範囲。PAT は設計上長命 |

---

## 6. 追加されたテストカバレッジ（Issue #77）

| テスト | ファイル | 検証内容 |
|--------|---------|---------|
| `TestEnsureFreshAccessTokenForSubject_PermanentFailureLenientBranchReturnsError` | `delegated_access_test.go` | ギャップ 2: 永続的な失敗後の 2 回目の呼び出しが dead bearer ではなく `ErrSubjectNotFound` を返す（`MarkRotationPermanentlyFailed` によりトークンが subject インデックスから削除される） |
| `TestLatestBySubjectTieBreaksOnInsertionOrder` | `subject_index_test.go` | ギャップ 3: 等しい有効期限のタイブレークが最も新しく登録されたトークンを返す |

既存の Phase B 委任アクセステスト 8 件はすべて引き続きパスします。auth パッケージのテストスイート全体: `go test ./internal/auth/... -count=1` → グリーン。

---

## 7. Go / No-Go 推奨

**推奨: GO — Phase B を本番環境対応として昇格させる。**

### 根拠

1. **正確性**: PR #76 レビューで特定された 3 つのギャップがすべて解決されました。ローテーションライフサイクルは完全な並行性モデル（singleflight・重複呼び出し・永続的な失敗・タイブレーク）において正確です。
2. **セキュリティ**: ループバック + 共有シークレットモデルは同一ホスト IPC のための確立されたアプローチであり、意図されたデプロイトポロジー内で既知の脆弱性はありません。
3. **テストカバレッジ**: 両方の新しい修正パスが回帰テストでカバーされています。既存のテストはグリーンを維持しています。実装は出荷可能な状態です。
4. **運用のシンプルさ**: 同一ホストデプロイに新しいインフラストラクチャは不要です。設定サーフェスは 1 つの env 変数と 1 つの `gateway.internal_addr` オプションです。
5. **既知の制限事項は許容範囲内**: L1〜L6 はすべて低影響か、明確なアップグレードパスを持つ延期項目です。主要ユースケース（同一ホスト上の長時間実行バックグラウンドウォッチでの認証期限切れ失敗を防ぐこと）をブロックするものはありません。

### 再評価の条件

- `copilot-review-mcp` がマルチコンテナデプロイに移行した場合は L5 を再評価する（Unix ソケット / mTLS）。
- subject ごとのスコープ制限が必要になった場合は L3 を再評価する（細かいスコープ）。
- ゲートウェイの再起動が頻繁な場合（ウォッチ重負荷デプロイで 2 時間未満の間隔）は L1 を再評価する（永続的な subject インデックス）。

---

## 8. 関連 Issue と PR

| 参照 | 説明 | ステータス |
|------|------|----------|
| Issue #70 | 認証ライフサイクル不一致スパイク | ✅ クローズ済み（スパイク完了） |
| Issue #72 | Phase B 設計 + PoC | ✅ クローズ済み（PR #76 マージ済み） |
| PR #76 | Phase B PoC 実装 | ✅ マージ済み |
| Issue #77 | Phase B ローテーション正確性ギャップ（ギャップ 2 + ギャップ 3） | ✅ この PR で修正済み |
| Issue #73 | Phase C: 構造化エラーコントラクト | 🟡 オープン（Phase B 採用決定待ちのためブロック中 — 今回ブロック解除） |
