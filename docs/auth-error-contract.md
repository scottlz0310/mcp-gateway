# 認証エラーコントラクト

> **Phase C — 構造化エラーコントラクト** (Issue #73)
>
> このドキュメントは、mcp-gateway とその利用者（MCP クライアント（公開 API）・upstream MCP サーバー（内部 API）・オペレーターツール）間のエラーコードコントラクトの権威的なリファレンスです。トリガー条件・ワイヤー表現・copilot-review-mcp の内部エラー分類へのマッピングを扱います。

---

## 1. 公開クライアントコントラクト

MCP クライアントは RFC 6750 Bearer トークンを使用してゲートウェイ保護ルートに対して認証します。すべてのエラーレスポンスは JSON ボディ `{"error": "<code>", "error_description": "..."}` と以下のヘッダーを含みます。

### 1.1 エラーコード

| エラーコード | HTTP ステータス | `WWW-Authenticate error=` | トリガー | 推奨クライアントアクション |
|---|---|---|---|---|
| `invalid_request` | 401 | **省略**（意図的 — §1.2 参照） | `Authorization` ヘッダーなし、またはヘッダーが `Bearer <token>` 形式でない | ゲートウェイ OAuth フローを開始する（`WWW-Authenticate` ヘッダーの `resource_metadata` URL に従う） |
| `invalid_token` | 401 | `error="invalid_token"` | トークンが期限切れ・暗号的に無効・または誤った audience 宛て | ゲートウェイ OAuth フローで再認証する |
| `upstream_error` | 503 | *（`WWW-Authenticate` ヘッダーなし）* | upstream OAuth プロバイダー（GitHub）がトークン検証中に 5xx を返したか、到達不能だった | 指数バックオフで再試行する。認証情報の変更は不要 |

### 1.2 `invalid_request` での `error=` 省略 — セキュリティ設計

RFC 6750 §3.1 は、リクエストに認証情報がまったくない場合に `error=` を省略することを許可しています。ゲートウェイは `Authorization` ヘッダーが不正形式（`Bearer <token>` 形式でない）の場合にも同じ省略を適用します。`extractBearer()` はどちらの場合も `""` を返し、どちらも `invalid_request` になります:

```
# invalid_request — error= 属性なし
WWW-Authenticate: Bearer realm="mcp-gateway", resource_metadata="<url>"

# invalid_token — error= あり
WWW-Authenticate: Bearer realm="mcp-gateway", error="invalid_token", error_description="...", resource_metadata="<url>"
```

**理由:** `error="invalid_request"` を省略することで、リクエストが不正形式なのか単に未認証なのかを明かさないようにしています。レスポンスは引き続き Bearer チャレンジと正規の MCP クライアントが必要とする `resource_metadata` URL を広告しています。Bearer スキーム自体は隠されていません。

実装参照: `internal/middleware/auth.go:writeUnauthorized()` — 条件 `if errCode == "invalid_token"` が `error=` 属性の出力を制御します。

### 1.3 後方互換性保証

上記の 3 つのコード（`invalid_request`、`invalid_token`、`upstream_error`）は `internal/middleware/auth_test.go` のテスト（`TestAuthMissingToken`、`TestAuthInvalidToken`、`TestAuthUpstreamError`）でカバーされています。それらのワイヤー形状を変更する場合は、これらのテストを更新し semver マイナーバージョンをインクリメントする必要があります。

---

## 2. 内部委任アクセスコントラクト

upstream MCP サーバー（例: copilot-review-mcp）は、内部リスナーで `POST /internal/v1/whoami` を呼び出すことで、ゲートウェイが管理する新鮮なアクセストークンを取得します。このエンドポイントは**ループバックのみ**で、事前共有シークレットで認証します。

エラーレスポンスはこのトラスト境界での情報露出を抑えるため `{"error": "<code>"}` のみ（`error_description` フィールドなし）です。

### 2.1 エラーコード

| エラーコード | HTTP ステータス | トリガー | 呼び出し元アクション |
|---|---|---|---|
| `method_not_allowed` | 405 | `POST` 以外のメソッド | HTTP メソッドを修正する。呼び出し元のバグ |
| `loopback_required` | 403 | ループバック以外のアドレスからのリクエスト | 呼び出し元が内部 API にループバック経由で接続していることを確認する。リスナーは常に `127.0.0.1:${MCP_GATEWAY_INTERNAL_PORT}` にバインド |
| `invalid_authorization` | 401 | `Authorization: Bearer` シークレットが欠けているか `MCP_GATEWAY_INTERNAL_SECRET` と一致しない | 共有シークレットの設定を修正する |
| `invalid_body` | 400 | 不正な JSON・ボディが 4 KiB を超える・未知のフィールド・JSON オブジェクト後の余分なバイト | リクエストボディを修正する |
| `missing_subject` | 400 | `subject` フィールドが省略または空（ホワイトスペースのみを含む） | 空でない subject を提供する |
| `subject_not_found` | 404 | 要求された subject のインメモリ subject インデックスにエントリーがない。ユーザーがこのインスタンスで一度も認証していない・セッションがパージされた・プロセスが最近再起動した（インメモリインデックスは再起動後に空から始まり、保護ルートで Bearer トークンが検証されるたびに再シードされる） | ユーザーに再認証を促す。プロセス再起動後はエラーが一時的な場合がある。ユーザーが保護ルートにアクセスするとインデックスが再構築される |
| `rotation_failed` | 502 | トークンが有効期限間近でローテーションを試みたが新鮮なトークンが得られなかった（一時的なプロバイダー/ネットワークエラーと GitHub トークンエンドポイントによる明示的な拒否を含む） | 短時間後に再試行する。エラーが続く場合はユーザーに再認証を促す。リフレッシュトークンが失効している可能性がある |
| `upstream_failure` | 502 | その他のリゾルバーエラー、またはリゾルバーが空のアクセストークンを返した | 短時間後に再試行する。継続する場合は `subject_not_found` として扱い再認証を促す |

### 2.2 命名の注記: `upstream_error` vs `upstream_failure`

これらは**異なるレイヤーの 2 つの別コード**であり、エイリアスではありません:

| コード | レイヤー | HTTP ステータス | 意味 |
|---|---|---|---|
| `upstream_error` | 公開 API（`middleware/auth.go`） | 503 | 受信 Bearer トークン検証時に *OAuth プロバイダー*（GitHub）に到達できない |
| `upstream_failure` | 内部 API（`internalapi/handler.go`） | 502 | *ゲートウェイリゾルバー* が要求された subject に使用可能なアクセストークンを生成できなかった |

命名の非対称性は意図的です。2 つのコードは別々のサブシステムに存在し、異なる対象者に向けられ、異なる再試行セマンティクスを持っています。統合すべきではありません。

### 2.3 概念カテゴリー: AUTH_CONTEXT_UNAVAILABLE

Issue #72（Phase B）では、「ゲートウェイがこの subject に使用可能な認証コンテキストを持っていない」という状態をカバーする単一のエラーコード `auth_context_unavailable` の導入が検討されました。Phase B の go/no-go 決定後、これは**却下**されました。コードベースに新しいエラーコードは追加されていません。

代わりに、既存の 2 つのコードがその概念をカバーしています:

| コード | コンテキストが利用不可な理由 |
|---|---|
| `subject_not_found` | この subject のトークンがキャッシュされていない（ユーザーがこのゲートウェイインスタンスで認証したことがない、またはキャッシュがパージされた） |
| `rotation_failed` | トークンは存在するがローテーションが新鮮なトークンを生成できなかった。一時的なプロバイダー/ネットワークエラーまたはリフレッシュトークンの永続的な拒否の可能性がある |

`subject_not_found` は常に再認証が必要です。`rotation_failed` はまず再試行すべきです。エラーが続く場合はエンドユーザーにゲートウェイの公開 OAuth フローで再認証を促してください。呼び出し元は継続的な `rotation_failed` を「再認証を促す」として扱う**べき**ですが、単発の一時的な発生は昇格前に再試行を保証します。

実装参照: `internal/auth/handler.go:EnsureFreshAccessTokenForSubject()` — 別個の型付きエラーとして `auth.ErrSubjectNotFound` と `auth.ErrRotationFailed` を返します。`internalapi/handler.go` がそれらを上記のコードにマッピングします。

---

### 2.4 OAuth 失敗診断エンドポイント

`GET /internal/v1/auth/failures` は、既存のループバック + 共有シークレット境界で直近 100 件の OAuth 失敗を最新順に返します。`limit=1..100` で件数を縮小できます。

| エラーコード | HTTP ステータス | トリガー |
|---|---|---|
| `method_not_allowed` | 405 | `GET` 以外 |
| `loopback_required` | 403 | ループバック以外からの接続 |
| `invalid_authorization` | 401 | 共有シークレット不一致 |
| `invalid_limit` | 400 | `limit` が 1 から 100 の整数でない |
| `diagnostics_unavailable` | 503 | failure reader が設定されていない |

レスポンスイベントにはトークン・authorization code・OAuth `state`・シークレット・プロバイダーレスポンスボディを含みません。永続的な解析の正本は OAuth 監査 JSON Lines ファイルであり、このエンドポイントのメモリ履歴はプロセス再起動時に消失します。

---

## 3. copilot-review-mcp マッピングコントラクト

このセクションはゲートウェイのエラーコードが copilot-review-mcp の内部エラー分類を通じてどのように伝播するかを説明します。両サービスのメンテナーに主に有用です。

### 3.1 ゲートウェイ内部 API → センチネルエラー

`copilot-review-mcp/internal/github/gateway_token_source.go` は `/internal/v1/whoami` レスポンスの HTTP ステータスコードを Go センチネルエラーにマッピングします:

| `/whoami` HTTP ステータス | ゲートウェイエラーコード | センチネルエラー |
|---|---|---|
| 200 | *（成功）* | — |
| 200（不正なボディ） | `expires_at` が欠けているか解析不能 | `ErrGatewayInvalidExpiry` |
| 401 | `invalid_authorization` | `ErrGatewayUnauthorized` |
| 403 | `loopback_required` | `ErrGatewayLoopbackRequired` |
| 404 | `subject_not_found` | `ErrGatewaySubjectGone` |
| 502 | `rotation_failed` | `ErrGatewayRotationFailed` |
| 502 | `upstream_failure`（または認識不能なボディ） | `ErrGatewayUpstreamFailure` |
| その他 4xx | `method_not_allowed` / `invalid_body` / `missing_subject` | `ErrGatewayBadRequest` |

`ErrGatewayUnauthorized`・`ErrGatewayLoopbackRequired`・`ErrGatewayBadRequest` は常に設定エラーを示します。正しく設定されたデプロイでは発生しないはずです。

`ErrGatewayRotationFailed` と `ErrGatewayUpstreamFailure` は copilot-review-mcp PR #34（Issue #33）以降の別々のセンチネルです。`gatewayTokenSource.Token()` が HTTP 502 レスポンスの JSON `error` ボディを解析して適切なセンチネルを発行するようになりました。

### 3.2 ウォッチマネージャー: センチネルエラー → `FailureReason`

`copilot-review-mcp/internal/watch/manager.go` はポーリング失敗を 3 つの `FailureReason` 値に分類します:

| `FailureReason` | 意味 |
|---|---|
| `AUTH_EXPIRED` | 認証コンテキストが期限切れ。ユーザーが再認証するまでウォッチを継続できない |
| `GITHUB_ERROR` | 認証期限切れでない GitHub API エラー（一時的な可能性あり） |
| `INTERNAL_ERROR` | ウォッチのセットアップまたはデータベース障害 |

マネージャーは `ghclient.IsAuthError(err)` と `ghclient.IsGatewayAuthError(err)` を使用して `AUTH_EXPIRED` と `GITHUB_ERROR` を区別します。`IsAuthError` は **GitHub API** からの HTTP 401 エラーを検出します。`IsGatewayAuthError` は再認証が必要なゲートウェイセンチネルを認識します。`ErrGatewayUpstreamFailure` は連続障害予算によって別途処理されます。`N` 回の連続障害後にウォッチは `AUTH_EXPIRED` に昇格します。

**現在の（実際の）マッピング:**

| センチネルエラー | `IsGatewayAuthError(err)` | `FailureReason`（現在） | 意味的に正確か |
|---|---|---|---|
| `ErrGatewaySubjectGone` | `true` | `AUTH_EXPIRED` | ✅ 修正済み ([scottlz0310/copilot-review-mcp PR #36](https://github.com/scottlz0310/copilot-review-mcp/pull/36)) |
| `ErrGatewayRotationFailed` | `true` | `AUTH_EXPIRED` | ✅ 修正済み ([scottlz0310/copilot-review-mcp PR #36](https://github.com/scottlz0310/copilot-review-mcp/pull/36)) |
| `ErrGatewayUpstreamFailure`（一時的、閾値未満） | `false` | `GITHUB_ERROR`（ウォッチ継続） | ✅ 修正済み ([scottlz0310/copilot-review-mcp PR #38](https://github.com/scottlz0310/copilot-review-mcp/pull/38)) |
| `ErrGatewayUpstreamFailure`（継続的、閾値超過） | `false` → 昇格 | `AUTH_EXPIRED` | ✅ 修正済み ([scottlz0310/copilot-review-mcp PR #38](https://github.com/scottlz0310/copilot-review-mcp/pull/38)) |
| GitHub API 401 | *（IsAuthError）* `true` | `AUTH_EXPIRED` | ✅ |
| GitHub API 5xx / その他 | `false` | `GITHUB_ERROR` | ✅ |

### 3.3 ツール呼び出しパス: `AuthErrorType`

copilot-review-mcp の**ツール呼び出し**が失敗した場合（バックグラウンドウォッチではなく）、エラーは `ClassifyGitHubError()` によって `autherr.AuthErrorType` に分類されます:

| `AuthErrorType` | 意味 |
|---|---|
| `AUTH_REQUIRED` | 認証情報がまったく存在しない |
| `REAUTH_REQUIRED` | 認証情報が期限切れ（GitHub 401） |
| `TOKEN_REFRESH_FAILED` | リフレッシュトークンが明示的に拒否された |
| `PERMISSION_DENIED` | GitHub 403 |
| `RATE_LIMITED` | GitHub レート制限（プライマリまたはセカンダリ） |
| `NOT_FOUND` | GitHub 404 |
| `VALIDATION_ERROR` | GitHub 400 / 422 |
| `TRANSIENT_UPSTREAM_ERROR` | GitHub 5xx（再試行可能） |

`ClassifyGitHubError` は GitHub API HTTP ステータスコードとゲートウェイセンチネルエラーの両方に基づいて構築されています。ゲートウェイセンチネルはより正確なセマンティクスを持つため、汎用的な HTTP ステータスチェックより先にチェックされます。

**ゲートウェイセンチネル → `AuthErrorType` マッピング（PR #32 時点）:**

| センチネル | `AuthErrorType` | 理由 |
|---|---|---|
| `ErrGatewayRotationFailed` | `TOKEN_REFRESH_FAILED` | ゲートウェイが `rotation_failed` を報告（トークン拒否・一時的なプロバイダー障害・不正なプロバイダーレスポンスを示す可能性あり）。継続する場合は再認証を推奨 |
| `ErrGatewaySubjectGone` | `REAUTH_REQUIRED` | Subject が削除または失効。再認証が必要 |
| `ErrGatewayUpstreamFailure` | `TRANSIENT_UPSTREAM_ERROR` | 一時的なリゾルバー障害。再試行で成功する可能性あり |
| `ErrGatewayUnauthorized` | `AUTH_REQUIRED` | 共有シークレットの設定ミス。使用可能なトークンなし |
| `ErrGatewayLoopbackRequired` | `AUTH_REQUIRED` | エンドポイントがループバック上にない。設定エラー |
| `ErrGatewayBadRequest` | `VALIDATION_ERROR` | リクエスト引数が拒否された。再試行しないこと |
| `ErrGatewayInvalidExpiry` | `TRANSIENT_UPSTREAM_ERROR` | 不正な whoami レスポンス（`expires_at` が欠けているか無効）。再試行で成功する可能性あり |

---

## 4. 既知のギャップ — すべて解決済み

Phase C ドキュメント作成時に特定された 3 つのギャップはすべて copilot-review-mcp で解決されました。以下のセクションは歴史的参照として保存されており、関連する PR にクロスリンクされています。

### ギャップ 1 — ✅ 解決済み (scottlz0310/copilot-review-mcp PR #36)

**`ErrGatewaySubjectGone` が `AUTH_EXPIRED` ではなく `GITHUB_ERROR` に分類されていた**

**場所:** `copilot-review-mcp/internal/watch/manager.go`

ウォッチの `gatewayTokenSource.Token()` 呼び出しが `ErrGatewaySubjectGone`（ゲートウェイからの HTTP 404）を返した場合、`IsAuthError` が GitHub API 401 パターンのみを認識するため `false` を返していました。ウォッチはそのため `FailureReason = GITHUB_ERROR` を設定していました。

**解決:** `ghclient.IsGatewayAuthError` が導入されウォッチマネージャーに組み込まれました。`ErrGatewaySubjectGone` と `ErrGatewayRotationFailed` に対して `true` を返し、ウォッチが両方に対して `FailureReason = AUTH_EXPIRED` を設定するようになりました。
[scottlz0310/copilot-review-mcp#31](https://github.com/scottlz0310/copilot-review-mcp/issues/31) で修正され、[scottlz0310/copilot-review-mcp PR #36](https://github.com/scottlz0310/copilot-review-mcp/pull/36) でリリースされました。

### ギャップ 2 — ✅ 解決済み (scottlz0310/copilot-review-mcp PR #32)

**ゲートウェイセンチネルエラーに `AuthErrorType` マッピングがなかった**

**場所:** `copilot-review-mcp/internal/github/classify.go`

ツール呼び出しがゲートウェイセンチネルエラーで失敗した場合、`ClassifyGitHubError` が `AuthErrorType` を生成しませんでした。

**解決:** すべてのゲートウェイセンチネルエラーの明示的なケースが `ClassifyGitHubError` に追加されました。現在のマッピングテーブルは §3.3 を参照してください。
[scottlz0310/copilot-review-mcp#32](https://github.com/scottlz0310/copilot-review-mcp/issues/32) で修正されました。

### ギャップ 3 — ✅ 解決済み (scottlz0310/copilot-review-mcp PR #34, Issue #33)

**`ErrGatewayUpstreamFailure` が `rotation_failed` と `upstream_failure` を混在させていた**

**場所:** `copilot-review-mcp/internal/github/gateway_token_source.go`

`gatewayTokenSource.Token()` がゲートウェイからのすべての HTTP 502 レスポンスを、JSON `error` ボディを読まずに同じセンチネル `ErrGatewayUpstreamFailure` にマッピングしていました。

**解決:** `gatewayTokenSource.Token()` が HTTP 502 レスポンスの JSON `error` フィールドを解析し、`{"error":"rotation_failed"}` に対して `ErrGatewayRotationFailed` を、`{"error":"upstream_failure"}`（または認識不能なボディ）に対して `ErrGatewayUpstreamFailure` を発行するようになりました。`N` 回の連続障害後の `ErrGatewayUpstreamFailure` の `AUTH_EXPIRED` への昇格も追加されました（[scottlz0310/copilot-review-mcp PR #38](https://github.com/scottlz0310/copilot-review-mcp/pull/38)）。
[scottlz0310/copilot-review-mcp#33](https://github.com/scottlz0310/copilot-review-mcp/issues/33) で修正され、[scottlz0310/copilot-review-mcp PR #34](https://github.com/scottlz0310/copilot-review-mcp/pull/34) でリリースされました。

---

## 5. オペレーターノート

### 5.1 ログフィールド

このリポジトリの構造化ログはエラー値に `"error"` ではなく `"err"` フィールドキーを使用します。以下のすべてのログエントリは `slog.Error` または `slog.Warn` で出力されます。

| ログメッセージ | レベル | キーフィールド | 意味 |
|---|---|---|---|
| `"upstream error during auth"` | Error | `err`、`path` | GitHub OAuth プロバイダーがトークン検証中に 5xx を返すかネットワーク障害。`upstream_error`（503）にマッピング |
| `"auth failed"` | Warn | `err`、`path` | トークン検証失敗。`invalid_token`（401）にマッピング |
| `"internalapi: whoami rotation failed"` | Warn | `subject`、`err` | リフレッシュローテーション失敗。`rotation_failed`（502）にマッピング |
| `"internalapi: whoami lookup failed"` | Warn | `subject`、`err` | その他のリゾルバー障害。`upstream_failure`（502）にマッピング |
| `"internalapi: whoami returned empty access token despite no error"` | Warn | `subject` | 防御的パス。`upstream_failure`（502）にマッピング |

### 5.2 再認証トリガー

以下のいずれかが観測された場合、ユーザーは新鮮な OAuth フローを完了する必要があります:

1. 公開 API が `invalid_token` を返す — ゲートウェイ Bearer トークンが期限切れ・無効・または要求されたリソースに対して有効でない（audience 不一致など）。`error_description` に関わらず `invalid_token` レスポンスはすべて再認証が必要です。
2. 内部 API が `subject_not_found` を返す — ユーザーがこのゲートウェイインスタンスでキャッシュされたセッションを持っていない（新しいデプロイ・キャッシュのパージ・またはユーザーがここで認証したことがない）。
3. 内部 API が `rotation_failed` を返す — トークンローテーションが新鮮なアクセストークンを生成できなかった（一時的な可能性あり。再認証を促す前に再試行してください）。

オペレーターは `401` レスポンスの `WWW-Authenticate` ヘッダーの `resource_metadata` パラメーターから再認証 URL を取得できます。

### 5.3 設定ヒント

| 症状 | 原因の可能性 | 確認事項 |
|---|---|---|
| 内部 API で `loopback_required`（403） | 呼び出し元がループバック経由で接続していない | upstream MCP サーバーが `127.0.0.1:${MCP_GATEWAY_INTERNAL_PORT}` を呼び出していることを確認する。リスナーは常に `127.0.0.1` のみにバインドされる（IPv6 ループバック `[::1]` は非対応） |
| 内部 API で `invalid_authorization`（401） | 共有シークレットが一致しない | ゲートウェイと upstream サーバーの両方の env で `MCP_GATEWAY_INTERNAL_SECRET` を確認する |
| `upstream_failure`（502）が継続する | 一時的なリゾルバーまたは GitHub API 障害、またはリゾルバーが空のアクセストークンを返した | GitHub のステータスを確認して再試行する。リゾルバーエラーのゲートウェイログ（`"err"` フィールド）を確認する |
| プロセス再起動後に `subject_not_found`（404） | インメモリ subject インデックスは再起動後に空から始まり Bearer トークン検証のたびに再シードされる | セッションが再起動後も維持されるように `MCP_GATEWAY_TOKEN_STORE_PATH` を永続ストレージに設定する。インデックスは subject ごとの最初の Bearer トークン検証で再構築される |
| すべてのリクエストで `upstream_error`（503） | GitHub OAuth プロバイダーに到達できない | GitHub のステータスと OAuth プロバイダー（`OAUTH_PROVIDER` で設定、デフォルト `github`）への外部ネットワークアクセスを確認する |
