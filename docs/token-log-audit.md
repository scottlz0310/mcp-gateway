# トークン値のログ漏洩監査記録

Issue [#193](https://github.com/scottlz0310/mcp-gateway/issues/193)(#24 Phase 4 の追跡漏れタスク)に基づく、全 `slog` call site の体系的監査の記録。

- 監査日: 2026-07-02
- 対象コミット: `2b377fe`(PR #189 マージ後の main)
- 対象: `slog.Info/Warn/Error/Debug/Log` 呼び出し 168 箇所(22 ファイル)、およびログに到達しうるエラー生成経路(`fmt.Errorf` 等)

## 結果サマリ

**トークン・シークレットの生値をログに出力する箇所は、意図的に設計された 1 箇所(setup mode のワンタイムトークン提示)を除き存在しない。**

| 確認観点 | 結果 |
| --- | --- |
| slog 引数へのトークン生値の直渡し | なし(意図的例外 1 箇所のみ、後述) |
| `err` 値経由の間接漏洩(URL・レスポンスボディ混入) | なし(後述) |
| HTTP アクセスログのクエリ文字列漏洩 | なし(`r.URL.Path` のみ出力、query 非出力) |
| トークン識別用ヘルパーのハッシュ化 | すべて sha256 ベース(後述) |

## 安全化ヘルパー一覧

トークン様の値をログで識別する必要がある場合、以下のヘルパーが使用されている。いずれも sha256 ベースで原文復元は不可能。

| ヘルパー | 定義箇所 | 実装 | 主な使用箇所 |
| --- | --- | --- | --- |
| `tokenFingerprint` | `internal/auth/handler.go` | sha256 → base64 の先頭 8 文字 | rotation ログ、authaudit の `TokenHash` |
| `tokenHash` | `internal/proxy/handler.go` | sha256 先頭 4 バイトの hex | proxy request ログ、401 invalidation ログ |
| `subjectHash` | `internal/upstreamoauth/callback.go` | sha256 先頭 4 バイトの hex | upstream OAuth authorization 完了ログ |

## パッケージ別の確認結果

- **internal/auth**(handler / session / tokenstore 系): エラーは全て `"err", err` 形式で、エラー生成側(store・provider)はパス・エンドポイント URL・固定文字列のみを含む。rotation ログと監査イベントは `tokenFingerprint` を使用。
- **internal/authaudit**: `Event` の構造化出力は timestamp / event / phase / provider / result / message / error_class / oauth_error / http_status / token_hash のみ。`TokenHash` フィールドには呼び出し側が `tokenFingerprint` 済みの値を渡している。
- **internal/proxy**: `tokenHash` 使用。`EnsureFreshAccessTokenForSubject` の失敗ログは err 自体を出力せず、エラー種別に応じた固定メッセージのみ(`handler.go` の `logMsg` 分岐)。
- **internal/upstreamoauth**: `subject_hash` / `state_prefix`(state key の先頭 8 文字)を使用。state はワンタイム・短命(認可フロー中のみ有効)のため、プレフィックス露出は許容と判断。
- **internal/middleware**: 認証失敗ログは `"err", err` 形式。`ValidateToken` 系エラーにトークン値は含まれない。アクセスログ(`logger.go`)は `r.URL.Path` のみでクエリ文字列を出力しないため、`/setup?token=` のようなクエリ経由のシークレットは漏れない。
- **internal/config**: 暗号化・鍵生成のイベントログのみ。secret / 鍵素材の値は出力しない。
- **internal/internalapi**: whoami 応答(トークンそのものを含む)はログに出さず、失敗時は subject と err のみ。
- **cmd/server/main.go**: 起動・設定エラーのみ。例外は下記の setup mode。

## err 経由の間接漏洩の確認

トークンエンドポイント・DCR・discovery の HTTP エラーをエラー文字列に含める箇所(`internal/upstreamoauth/{flow,callback,refresher,dcr}.go`、`internal/auth/provider/oidc.go`)は、いずれも以下の条件を満たす:

- **非 2xx のエラーレスポンスのみ**をボディとして読む(トークンを含む成功レスポンスはエラーに載らない)
- `io.LimitReader(resp.Body, 256)` で 256 バイトに制限
- エラーに含まれる URL はエンドポイント URL のみ(トークンをクエリに載せる実装はない)

## 意図的例外: setup mode のワンタイムトークン

`cmd/server/main.go` の setup mode 起動ログは、ワンタイム setup token の生値を `setup_url` と `token` として出力する。これは初回セットアップでオペレーターがコンソールログから setup URL を取得する**機能そのもの**であり、意図的な設計である:

- トークンは短命(期限切れで `408`)かつセットアップ完了後は無効
- このログを閲覧できる者(コンソール・`docker logs` へのアクセス権保持者)は、セットアップを実行する権限者と同一
- `docs/operations.md` に「トークンは短命のシークレットとして扱ってください」と明記済み

この例外を新設・拡大する変更は、本監査記録と `CONTRIBUTING.md` のログポリシーの更新を伴うこと。

## 再発防止

- ログ・機密情報の取り扱いポリシーは `CONTRIBUTING.md` の「Logging & Secrets」を参照
- トークンを扱う主要フローのログにトークン生値が現れないことは回帰テストで固定している(`internal/auth/log_leak_test.go`、`internal/proxy/handler_test.go` の該当テスト)
- 新たにトークン・シークレットを扱う経路を追加する PR では、レビューで本ポリシーへの準拠を確認する
