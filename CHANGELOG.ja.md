# Changelog

すべての変更は [Keep a Changelog](https://keepachangelog.com/ja/1.1.0/) に従い、
バージョニングは [Semantic Versioning](https://semver.org/lang/ja/) に従う。

## [Unreleased]

### 修正

- TLS リスナーはデフォルトで HTTP/1.1 のみを話すようになり、ALPN のオファーから HTTP/2 を除外した（[#204](https://github.com/scottlz0310/mcp-gateway/issues/204)）
  - Node.js 26 以降の fetch クライアント（undici）は h2 をネゴシエートするが、他のリクエストが in-flight の間はボディ付きリクエストを多重化しないため、終わらない MCP Streamable HTTP の SSE GET が後続のすべての POST をクライアントタイムアウトまで飢餓させていた（mcp-resource-subscriber では `MCP error -32001: Request timed out`、ゲートウェイログでは副次的な 502 `Content-Length ... but only wrote 0 bytes` proxy error として観測）。ゲートウェイ自体の h2 → h1 中継は正常であることを検証済みで、キューイングは完全にクライアント内部で発生していた。
  - 新環境変数 `MCP_GATEWAY_ENABLE_HTTP2`（デフォルト `false`）: 影響を受けないクライアントのみを想定するデプロイでは TLS リスナーの HTTP/2 を再有効化できる。
  - ALPN ポリシーを固定する回帰テスト（`TestListenAndServeALPN`）を追加。

## [0.9.0] - 2026-07-10

### 追加

- ローカル HTTPS（TLS 終端）サポート（[#201](https://github.com/scottlz0310/mcp-gateway/issues/201)）
  - 新環境変数 `MCP_GATEWAY_TLS_CERT_PATH` / `MCP_GATEWAY_TLS_KEY_PATH`: 両方に PEM 証明書・秘密鍵のパスを設定すると、ゲートウェイ（初回セットアップウィザードを含む）が `http.Server.ListenAndServeTLS` で TLS 付きで listen する。
  - 起動時のフェイルファスト検証: 片方のみの設定、ファイル欠如、ディレクトリ指定は明示的なエラーで起動を中断する。自己署名証明書の自動生成フォールバックは行わない（ローカル証明書の準備はデプロイ側の責務。例: Mcp-Docker の `setup-tls`）。
  - `MCP_GATEWAY_PUBLIC_URL` 未設定時のデフォルト公開 URL は、TLS 有効時に `https` スキームで導出されるようになり、OAuth コールバックとディスカバリメタデータがリスナーと整合する。

## [0.8.0] - 2026-07-03

### セキュリティ

- 全 `slog` call site を対象としたトークン値のログ漏洩監査を完了（#24 Phase 4 の残タスク）。意図的かつ文書化済みの setup mode ワンタイムトークン提示を除き、トークン・シークレットの生値はどこにもログ出力されないことを確認した。（[#193](https://github.com/scottlz0310/mcp-gateway/issues/193)）
  - `docs/token-log-audit.md` — 監査記録: 対象範囲、パッケージ別の確認結果、安全化ヘルパー一覧（`tokenFingerprint` / `tokenHash` / `subjectHash`、いずれも sha256 ベース）、エラー文字列経由の間接漏洩の確認、setup mode 例外の根拠
  - `CONTRIBUTING.md` — 「Logging & Secrets」ポリシーを新設: ログでのトークン識別には sha256 ベースのヘルパーを必須とし、秘密値を送信するエンドポイント（token endpoint）のレスポンスボディはエラー文字列に含めない。秘密値を送信しないエンドポイント（discovery・DCR）のみ非 2xx かつ 256 バイト制限の snippet を許容。アクセスログにクエリ文字列を含めない
  - token endpoint のエラー処理（`internal/upstreamoauth` の authorization-code exchange / refresh / client_credentials）で、非 2xx レスポンス本文をエラー文字列へ含めないよう修正 — AS が送信された authorization code・refresh token・client secret をエラー本文へ反映した場合にログへ漏洩するため（PR #194 レビュー指摘）。HTTP status と OAuth error code のみを残す（`tokenEndpointError`）
  - `provider.NormalizeOAuthErrorCode` を既知の OAuth / OIDC / GitHub error code の allowlist 分類へ変更し、未知値は固定値 `unknown_error` へ落とすよう修正 — 文字種・長さの制限だけでは、AS が秘密値を `error` フィールド自体へ反映した場合に生値がログへ残るため（PR #194 レビュー指摘）。`tokenEndpointError`・authorization callback の `error` クエリ・監査イベントの `oauth_error` フィールドの全呼び出し元が一括で fail-closed になる
  - トークン生値がログに現れないことを固定する回帰テストを追加: builtin authorization-code + refresh フローと GitHub rotation の成功・失敗両経路（`internal/auth/log_leak_test.go`）、秘密値を反映する AS を模した token endpoint 3 経路（`internal/upstreamoauth/log_leak_test.go`）、proxy の 401 invalidation 経路（`internal/proxy/handler_test.go`）

### 修正

- `EnsureFreshAccessTokenForSubject`（Phase B delegated access）が builtin mode（`OAUTH_PROVIDER=builtin`）で gateway 発行の JWT ではなく GitHub provider アクセストークンを返すよう修正。従来は OAuth token 交換時に取得した GitHub アクセストークンが identity 解決にのみ使われて破棄され、トークンストアには gateway JWT しか残らなかった。そのため delegated access の呼び出し元（review-raven の `upstream_provider_token=true` ルートや `/internal/v1/whoami` エンドポイントなど）は gateway JWT を利用可能な GitHub bearer トークンとして受け取ってしまい、ユーザーの GitHub セッションが実際には有効なままでも、以降のすべての GitHub API 呼び出しが `401 Unauthorized` で失敗していた。（[#188](https://github.com/scottlz0310/mcp-gateway/issues/188)）
  - `TokenRecord.ProviderAccessToken` — キャッシュエントリに紐づく provider アクセストークンを保持する新フィールド。authorization-code フロー・device フローの両方で設定され、`refresh_token` grant でも引き継がれる（refresh token の猶予期間が、それと共に発行された access-token キャッシュエントリの寿命より長く続く可能性があるため、refresh token ストア経由で引き継ぐ）。
  - `TokenStore.SaveProviderAccessToken` / `RefreshTokenStore.SaveProviderAccessToken` + `LookupProviderAccessToken` — 新規ストアメソッド（mem・file・SQLite の `RefreshTokenStore` 実装すべてに対応）。
  - `ValidateToken` は builtin mode ではキャッシュヒット時に非 builtin 用の GitHub rotation 経路を呼ばなくなった。将来 builtin mode の rotation 対応が入った際に顕在化しうるトークン漏洩リスクを事前に塞ぐもの（rotation 自体は follow-up として未実装 — `builtinProvider.RefreshToken` は引き続き `ErrRefreshNotSupported` を返す）。
  - `docs/configuration.md` — builtin mode では `github_refresh_enabled` の設定に関わらず、GitHub アクセストークンが常に `tokens.json` / refresh token ストアに永続化される旨を追記。また builtin mode の delegated access には永続トークンストアが実質必須である旨を制限事項に追記（in-memory ストア構成では JWT に紐付けた GitHub アクセストークンがトークンキャッシュ TTL 経過または再起動で失われ、JWT が有効なまま delegated access だけが再認証を要求し続けるため）。

### 追加

- builtin mode（`OAUTH_PROVIDER=builtin`）で GitHub provider アクセストークンの自動 rotation に対応（[#190](https://github.com/scottlz0310/mcp-gateway/issues/190)）
  - `builtinProvider.RefreshToken` が GitHub OAuth への委譲実装になった（従来は常に `ErrRefreshNotSupported` を返していた）
  - builtin mode 専用の rotation ロジック（`tryBuiltinRotationWithAttempt` / `runBuiltinRotation`）を新設。非 builtin mode の rotation（cache key = provider トークン自体を差し替える設計）とは異なり、cache key（gateway JWT）はそのままに、record 内の `ProviderAccessToken` / `ProviderRefreshToken` / `ProviderAccessExpiry` のみを更新する。`EnsureFreshAccessTokenForSubject`（Phase B delegated access）の builtin 分岐にのみ組み込み、`ValidateToken` のキャッシュヒット分岐（PR #189 で追加した「非 builtin rotation を呼ばない」ガード）には手を入れていない — JWT 検証と provider トークンの rotation は builtin mode では独立した関心事であり、rotation が必要になるのは delegated access が provider トークン自体を使う場面のみのため
  - `RefreshTokenStore.SaveProviderRefresh` / `LookupProviderRefresh`（`ProviderRefreshToken` + `ProviderAccessExpiry`）を新設（mem・file・SQLite の3実装）。`tokenAuthCode` / `tokenDeviceGrant` / `tokenRefresh` の builtin 分岐でこれらを使い、rotation に必要なメタデータをアクセストークン TokenStore エントリの sweep 後も refresh token 経由で引き継げるようにした（既存の `ProviderAccessToken` と同じパターン）
  - delegated rotation と gateway refresh を refresh-token family 単位で直列化し、rotation 成功時は current JWT と active refresh-token entry を同じ provider token 世代へ更新する。永久失敗時は family 全体を revoke し、失効済み metadata から新しい lineage が復活しないようにした
  - `tokenDeviceGrant` の builtin 分岐が誤ったキー（`completed.AccessToken`、非 builtin mode 用のキー）で provider refresh metadata を保存していたため実質 no-op になっていたバグを修正し、正しいキー（gateway JWT）で保存するようにした
- RFC 7009 OAuth 2.0 Token Revocation（`POST /revoke`）を実装（[#192](https://github.com/scottlz0310/mcp-gateway/issues/192)）
  - `token` + 任意 `token_type_hint`（`access_token`/`refresh_token`）を受け付け、hint に関わらず両方の失効経路を試行する。未知・期限切れ・二重失効のトークンでも常に `200 OK` を返す（RFC 7009 §2.2）
  - refresh token の失効は既存の RFC 6819 family 失効（`RevokeFamily`）を再利用し、ファミリー全体を無効化する
  - builtin mode（`OAUTH_PROVIDER=builtin`）の gateway JWT は、`jti` クレームによる失効 denylist を新設して即時失効に対応。JWT 検証はステートレスなため、TokenStore からのキャッシュ削除だけでは有効期限（デフォルト 90 日）まで生き続けてしまう問題を解消した。denylist は `RefreshTokenStore` の SQLite DB（`tokens.json.refresh.db`）に相乗りし、既存の Sweep サイクルで自然に失効エントリを掃除する
  - refresh token の失効時は、紐づく現行アクセストークン（gateway JWT）の `jti` も即座に denylist へ登録し、将来のローテーションだけでなく既発行トークンも即時失効させる
  - `.well-known/oauth-authorization-server` の discovery メタデータに `revocation_endpoint` を追加
  - non-builtin mode（GitHub トークンを直接使用）ではゲートウェイ側のローカルキャッシュのみ失効させる。GitHub 側のトークン自体の失効 API 呼び出しはスコープ外（別 issue で検討）
- `Mcp-Session-Id` 双方向透過の回帰テストと診断ログ・トラブルシュート手順を追加（[#182](https://github.com/scottlz0310/mcp-gateway/issues/182)）
  - `proxy request` / `proxy response` ログに `mcp_session_id_present` フィールドを追加（セッション ID の実値はログに出力しない）
  - `handler_test.go` に request・response 双方向透過の回帰テスト追加
  - `docs/operations.md` に正しい MCP 初期化シーケンス・切り分け手順・gateway/upstream エラー判別方法を追加
- 新ルートオプション `upstream_provider_token=true` を追加し、review-raven 等の upstream へ gateway JWT ではなく該当 subject の provider アクセストークン（builtin mode: GitHub アクセストークン）を注入できるようにした（[#186](https://github.com/scottlz0310/mcp-gateway/issues/186)）
  - `EnsureFreshAccessTokenForSubject` でサブジェクトの provider アクセストークンを解決し、`ProviderTokenSource` インターフェース経由で proxy へ注入する `NewProviderTokenMiddleware` を新設
  - `upstream_oauth` / `upstream_bearer_token_env` / `auth=none` との同時指定を fail-closed で拒否
  - provider token が未解決・失効・rotation failure の場合は `401` + `WWW-Authenticate` でフェールクローズ
  - upstream `401` 時は provider token 委任経路のみを対象とし、gateway JWT の validation cache を誤って失効させないようにした
  - `docs/configuration.md` に `upstream_provider_token` オプションと「プロバイダートークン委任」セクションを追加

### 変更

- プライマリトークンストア（TokenStore）を平文 JSON ファイル（`tokens.json`）から SQLite へ移行し、#135 でリフレッシュトークンストアに対して始まったストレージ統合を完了（[#191](https://github.com/scottlz0310/mcp-gateway/issues/191)）
  - アクセストークンとリフレッシュトークンが単一の SQLite データベース（`<token-store-path>.refresh.db`）を共有するようになった: 単一ファイル・単一 writer ロック・単一トランザクション境界でゲートウェイの論理トークン状態全体を管理する。ファイル名は歴史的経緯の `.refresh.db` を維持し、アップグレード時に既存データベースを再利用でき、旧バージョンへのロールバック時にも denylist・リフレッシュ状態が期待されるパスから参照できるようにした
  - フィールド更新（`SaveProviderRefresh` / `SaveProviderAccessToken` / `SaveNonce` / `SaveJti` / `MarkRotationFailed`）は有効期限ガード付きの単一 `UPDATE` 文になり、file ストアのファイル全体 rewrite + 手動インメモリロールバックのパターンを置き換えた。期限切れエントリの掃除も全走査 + rewrite からインデックス付き `DELETE` になった
  - 自動ワンタイムマイグレーション: 既存の `tokens.json` は初回起動時に単一トランザクションでインポートされ、`tokens.json.migrated` にリネームされる（#135 のパターン踏襲）。マイグレーション失敗時は元ファイルを残したまま起動を中止する
  - TokenStore 契約テストを SQLite 実装にも適用。file-backed 実装はマイグレーション元フォーマットとしてレガシー扱いで残置
  - `docs/configuration.md` の「トークン永続化」を実装に合わせて全面改訂: `MCP_GATEWAY_TOKEN_STORE_PATH` のベースパスとしての意味、共有データベース構成、マイグレーション挙動、バックアップ除外対象（`tokens.json.refresh.db` + `-wal`/`-shm` + `*.migrated`）。PR #189 がプライマリストアの SQLite バックエンドに言及済みだったドキュメントと実装の乖離（#191 で指摘）もこれで解消

## [0.7.0] - 2026-06-21

### 追加

- upstream OAuth 委任: `upstream_oauth` を設定した MCP ルートに対して、ユーザーごとの upstream OAuth フローを gateway が仲介するエンドツーエンド実装（[#84](https://github.com/scottlz0310/mcp-gateway/issues/84)）
  - **ルートオプション解析・バリデーション**（[#113](https://github.com/scottlz0310/mcp-gateway/issues/113)）: `ROUTE_*` 環境変数および `config.yaml` で `upstream_oauth=auto|<issuer-url>` / `upstream_oauth_scope` を受け付ける。`upstream_oauth` と `upstream_bearer_token_env` の同時指定は fail-closed で拒否。YAML `null` / blank は「不在（無効）」として扱う
  - **メタデータ検索と Dynamic Client Registration**（[#114](https://github.com/scottlz0310/mcp-gateway/issues/114)）: RFC 9728 の Protected Resource → AS メタデータ 2 段検索、明示 issuer URL からの RFC 8414 1 段検索、RFC 7591 DCR（200 / 201 両対応）。per-route 遅延検索 + in-memory AS メタデータキャッシュ。`upstream_clients.json` を atomic write（0600）で永続化
  - **upstream ユーザートークンストア**（[#115](https://github.com/scottlz0310/mcp-gateway/issues/115)）: `UpstreamTokenStore` インターフェース（`Save` / `Lookup` / `Delete` / `LookupForRefresh` / `Sweep`）。in-memory 実装と `upstream_tokens.json` file-backed 実装。ディスク上のキーは `sha256(subject + "\x00" + routeName)` の hex 文字列（identity をディスクに書かない）。atomic write（0600）
  - **PKCE 付き認可フロー**（[#116](https://github.com/scottlz0310/mcp-gateway/issues/116)）: `NewAuthorizeMiddleware` が PKCE `code_verifier` / `code_challenge`（S256）を生成し、OAuth state を 10 分 TTL で保存してから認可エラーを返す。`GET /upstream/callback/{route-name}` が `state` 検証・`code` + `code_verifier` PKCE 交換・upstream アクセストークン保存を行う。state 期限切れは fail-closed
  - **proxy トークン注入と 401 クリーンアップ**（[#117](https://github.com/scottlz0310/mcp-gateway/issues/117)）: upstream の `access_token` を `Authorization: Bearer` ヘッダーとしてプロキシリクエストに注入。upstream `401` 発生時に古い upstream トークンを削除し、次のリクエストで認可フローを再開させる
  - **事前リフレッシュと 401 透過リトライ**（[#118](https://github.com/scottlz0310/mcp-gateway/issues/118)）: 有効期限前に upstream トークンをリフレッシュ。`401` 発生時は `singleflight` で subject + route ごとに排他しながら refresh + retry。`GetBody()` によるリクエストボディの再送。`expires_in ≤ 0` は有効期限不明として事前リフレッシュしない。永続的なリフレッシュ失敗ではトークン削除後に認可フローへ誘導
  - **`client_credentials` グラント** と `upstream_oauth_grant` ルートオプション（[#166](https://github.com/scottlz0310/mcp-gateway/issues/166)）: `upstream_oauth_grant=client_credentials` でサーバー間トークン取得（ユーザー操作不要）。`upstream_oauth_grant=authorization_code`（デフォルト）は PKCE ユーザーフローを維持。グラント変更時に DCR 再登録・トークン再取得
  - **期限切れ upstream トークンへの `LookupForRefresh` 対応**（[#171](https://github.com/scottlz0310/mcp-gateway/issues/171)）: `UpstreamTokenStore.LookupForRefresh` が期限切れレコードも返すため、`RefreshAfter401` がアクセストークン期限切れ後も refresh_token で再取得可能になる

- RFC 8252 §7.1 opaque-form カスタムスキーム redirect URI のサポート（[#125](https://github.com/scottlz0310/mcp-gateway/issues/125)）
  - `Host` または `Opaque` が空でないカスタムスキーム URI を許可（例: `com.example.app:/oauth2redirect/provider`）
  - host も opaque も持たないカスタムスキーム URI は引き続き fail-closed で拒否
  - fragment 付き URI はすべてのスキームで拒否

- Authorization Code フローにおける OIDC `nonce` claim 対応（OIDC Core §3.1.3.7）（[#123](https://github.com/scottlz0310/mcp-gateway/issues/123)、[PR #159](https://github.com/scottlz0310/mcp-gateway/pull/159)）
  - `Session.Nonce` が認可セッションを通じて nonce を保持。`/authorize` が `nonce` クエリパラメータを読み取りセッションに保存
  - `ExchangeCodeResult.Nonce` が `tokenAuthCode` → `writeTokenResponse` → `generateIDToken` の呼び出し連鎖を通じて nonce を伝播
  - nonce が空でない場合のみ `id_token` payload に `nonce` claim を含める（OIDC Core §3.1.3.7 準拠）。device flow / refresh flow は仕様通り `""` で呼び出す

### 修正

- `refresh_token` フローの `id_token` に OIDC nonce を伝播するよう修正（OIDC Core §12.2）（[#160](https://github.com/scottlz0310/mcp-gateway/issues/160)）
  - `TokenRecord`・`memEntry`・`fileEntry`・`memRTEntry`・`fileRTEntry`・`sqliteRefreshTokenStore` に `Nonce` フィールドを追加し、アクセストークンストアとリフレッシュトークンストア両方で永続化
  - `RefreshTokenStore` に `SaveNonce` / `LookupNonce` を追加し、アクセストークン TTL を超えても nonce を保持
  - `tokenRefresh` がローテーション後の RT 発行後に `SaveRefreshTokenNonce(newRT, nonce)` を呼ぶことで、連続 refresh でも nonce が引き継がれる
  - `SaveTokenNonce` の空文字列ガードを削除し、nonce なしの後続グラントで既存 nonce を正しくクリアできるよう修正

- `builtin` プロバイダーの `ValidateToken` が OAuth callback 時の identity resolution で GitHub API に委譲するよう修正（[#162](https://github.com/scottlz0310/mcp-gateway/issues/162)）

- OIDC Discovery（`/.well-known/openid-configuration`）に PKCE・grant type・registration・device authorization の metadata を追加し、OIDC クライアントが対応フローを検出できるよう修正（[#122](https://github.com/scottlz0310/mcp-gateway/issues/122)）

- `buildResourceAudienceMap` がルート名キーと URL 形式キー（`routeResource` 由来の `resourceURL`）の両方をインデックスするよう修正。RFC 8707 クライアントがリソース URL を送った場合の `invalid_target` エラーを解消（[#175](https://github.com/scottlz0310/mcp-gateway/issues/175)）
  - gateway-wide PRM 検索と `"/"` prefix ルートの resource 解決も追加し、ルートプレフィックスルートが正しく解決されるよう対応

- Dynamic Client Registration が登録ごとに一意の `client_id` を生成するよう修正（RFC 7591 §3.2.1 準拠）（[#177](https://github.com/scottlz0310/mcp-gateway/issues/177)、[PR #178](https://github.com/scottlz0310/mcp-gateway/pull/178)）
  - 従来はルート名から決定論的に生成した `client_id` を再利用していたため、DCR レコード失効後の再登録で競合が発生していた

- `NewAuthorizeMiddleware` が `302 Found` の代わりに `200 OK` + JSON-RPC エラー（code `-32001`、`type: "upstream_authorization_required"`）を返すよう変更し、MCP クライアントがレスポンスを接続失敗と誤解して認証フローを最初からやり直す再認証ループを防止（[#179](https://github.com/scottlz0310/mcp-gateway/issues/179)、[PR #180](https://github.com/scottlz0310/mcp-gateway/pull/180)）
  - `error.data.authorization_url` に PKCE パラメーター付きの upstream 認可エンドポイント URL を埋め込む。クライアントはこの URL をブラウザで開いてから MCP リクエストをリトライする
  - `Cache-Control: no-store` / `Pragma: no-cache` ヘッダーを付与し、OAuth state パラメーターがキャッシュされないよう対応

### ドキュメント

- README・`docs/configuration.md`・`docs/operations.md` に、実装済みだが未記載だった upstream OAuth 委任の内容を追記（[PR #174](https://github.com/scottlz0310/mcp-gateway/pull/174)）
  - Key Features に `authorization_code` / `client_credentials` upstream OAuth 委任・proactive refresh・401 透過リトライを追加
  - エンドポイント表に `/upstream/callback/{routeName}` と OIDC 系エンドポイント（`/jwks`・`/userinfo`・`/.well-known/openid-configuration`）を追加
  - 重要パスファイル表に `upstream_clients.json` / `upstream_tokens.json` を追加
  - `docs/operations.md` に upstream OAuth トラブルシュートセクションを新設（トークン取得失敗・リフレッシュ失敗・`upstream_clients.json` リセット）
- アーキテクチャドキュメントを 5 本立て → 6 本立てに更新: コンポーネント表・データフロー図・設計原則に squirrel-notifier を追加（[PR #174](https://github.com/scottlz0310/mcp-gateway/pull/174)）

## [0.6.0] - 2026-06-17

### 追加

- 実行時状態ファイルのデフォルトパスを OS のユーザー状態ディレクトリに変更（[#144](https://github.com/scottlz0310/mcp-gateway/issues/144)）
  - `MCP_GATEWAY_KEY_PATH`・`MCP_CONFIG_FILE`・`MCP_GATEWAY_TOKEN_STORE_PATH` のデフォルトが OS ユーザー状態ディレクトリ（Windows: `%LOCALAPPDATA%\mcp-gateway\`、Linux: `$XDG_STATE_HOME/mcp-gateway/` → `~/.local/state/mcp-gateway/`、macOS: `~/Library/Application Support/mcp-gateway/`）に変更
  - 起動時に `MkdirAll 0700` でディレクトリを自動作成。クリーンインストールの初回起動失敗が解消
  - Docker 環境では引き続き環境変数で上書きするため影響なし。変更が適用されるのは非コンテナ環境のみ
- `docs/configuration.md`・`README.md`・`README.ja.md` のデフォルトパス記載を #144 実装と同期（[#147](https://github.com/scottlz0310/mcp-gateway/issues/147)）
  - 環境変数テーブルを `{state-dir}` 記法に更新し、OS 別パスの脚注を追加
- GitHub App 推奨 Permission 設定をドキュメントに追記（[#145](https://github.com/scottlz0310/mcp-gateway/issues/145)）
  - `README.md`・`README.ja.md`: Permission セクションを拡充。`review-raven` / `github-mcp-server` upstream が必要とする Repository 権限（Contents / Issues / Pull requests / Metadata）と Account 権限（Email addresses）をテーブル形式で説明
  - `examples/copilot-review-routing/.env.example`: GitHub App 作成コメントに同内容の推奨 Permission を追記
- Device Authorization Grant のバグ修正: `/callback` が GitHub code を `/device_callback` に転送し、二重 ExchangeCode で `bad_verification_code` が発生する問題を修正（[#143](https://github.com/scottlz0310/mcp-gateway/issues/143)）
  - `Callback` ハンドラが `device:` プレフィックスの state を検出し、`ApproveDevice` を直接呼ぶことで二重 ExchangeCode を回避
  - 回帰防止のため `TestCallbackDeviceFlowFallback` を追加
  - `examples/copilot-review-routing/.env.example`: GitHub App callback URL 説明を更新
- GitHub Apps トークン有効期限対応（`tryGitHubRotation` の `ghu_`/`ghr_` 互換）（[#140](https://github.com/scottlz0310/mcp-gateway/issues/140)）
  - `ghu_`（user access token）と `ghr_`（refresh token）が `RefreshToken` / `tryGitHubRotation` でプレフィックス検証なしにそのまま動作することを確認
  - `internal/auth/provider/github_test.go`: `ghu_` access token 取得と `ghr_` → `ghu_` リフレッシュローテーションのテストケースを追加
  - `internal/auth/delegated_access_test.go`: `ghu_`/`ghr_` の有効期限付きトークン ローテーション全経路をカバーする `TestEnsureFreshAccessTokenForSubject_GhuTokenRotation` を追加
  - `docs/configuration.md`: GitHub App 側の "Expire user authorization tokens" 有効化手順と `MCP_GATEWAY_GITHUB_REFRESH_ENABLED=true` 設定手順を追加
  - `README.md` / `README.ja.md`: 有効期限付きトークン注記を「対応済み」に更新
- GitHub OAuth Apps から GitHub Apps（user-to-server OAuth）へのプロバイダー切り替え（[#139](https://github.com/scottlz0310/mcp-gateway/issues/139)）
  - `ghu_` ユーザーアクセストークン（GitHub Apps）を `gho_`（OAuth Apps）と同様に受け入れ可能 — プレフィックス検証ロジックが存在しないためコード変更不要
  - README / README.ja.md: Step 1 を「GitHub App を作成」に更新。`/callback` と `/device_callback` の両コールバック URL 登録手順、最小 Permissions（`Email addresses: Read-only`）、OAuth Apps からの移行手順を追記
  - docs/configuration.md: "GitHub OAuth App" 参照を "GitHub App" に統一
  - 内部: テストフィクスチャを `ghu_` プレフィックスに更新、factory エラーメッセージを "GitHub App credentials" に更新
- OAuth 監査ログと診断機能を追加（[#102](https://github.com/scottlz0310/mcp-gateway/issues/102)）
  - authorize、callback、token exchange、identity resolution、refresh、provider rotation の成否を構造化イベントとして記録
  - OS のユーザー state 領域を既定とし、Git worktree 外へ機密情報を除外した JSON Lines をサイズ・日数・世代数でローテーション保存
  - 既存の loopback + shared secret internal API に `GET /internal/v1/auth/failures` を追加
- OIDC プロバイダーのサポートを追加（[#98](https://github.com/scottlz0310/mcp-gateway/pull/98)）
  - agy CLI をサポートするため、mcp-gateway を OIDC Identity Provider として動作可能に
  - OIDC 用の RSA 秘密鍵の永続化をサポート
- RFC 8252 カスタム URL スキーム redirect_uri のサポートを追加（[#121](https://github.com/scottlz0310/mcp-gateway/issues/121)）
  - agy CLI 等のネイティブアプリクライアントが `antigravity://oauth-callback` 等のカスタム URL スキームを redirect_uri として使用可能に
  - デフォルト許可スキーム: `antigravity`、`antigravity-insiders`
  - `MCP_GATEWAY_ALLOWED_REDIRECT_SCHEMES` 環境変数または `gateway.allowed_redirect_schemes`（config.yaml）で上書き可能

### 修正

- OIDC Discovery（`/.well-known/openid-configuration`）に PKCE、grant type、registration、device authorization の metadata を追加し、OIDC クライアントが対応フローを検出できるよう修正（[#122](https://github.com/scottlz0310/mcp-gateway/issues/122)）
- exact-prefix リクエストで upstream のベースパスに末尾スラッシュを付与せず、そのまま転送するよう修正（[#111](https://github.com/scottlz0310/mcp-gateway/issues/111)）
- upstream 転送時にルーティングプレフィックスをストリップする機能を追加（[#108](https://github.com/scottlz0310/mcp-gateway/issues/108)）
  - `github-mcp-server` や `playwright-mcp` などパスを厳格に検証する MCP サーバーで発生していた `405 Method Not Allowed` を解消するため、プロキシ転送前にルーティングプレフィックス（例: `/mcp/github`）をリクエストパスから除去するよう修正
  - upstream にベースパスがある場合（例: `https://mcp.cloudflare.com/mcp`）も正しくパスが結合されるよう、`SetURL` の呼び出し前にプレフィックスを除去する実装に変更
- github-mcp-server プロキシ時の認証失敗を修正（[#104](https://github.com/scottlz0310/mcp-gateway/pull/104)）
  - docker-compose.yml で mcp-gateway の環境変数に `GITHUB_PERSONAL_ACCESS_TOKEN` を追加
  - `/mcp/github` ルートに `upstream_bearer_token_env=GITHUB_PERSONAL_ACCESS_TOKEN` を指定し、クライアント側のトークン期限切れが github-mcp-server に伝播して認証エラーになる問題を解消
- redirect_uri 許可ホストの設定経路を追加（[#100](https://github.com/scottlz0310/mcp-gateway/issues/100)）
  - `MCP_GATEWAY_ALLOWED_REDIRECT_HOSTS` 環境変数（カンマ区切り）および `gateway.allowed_redirect_hosts` 設定（config.yaml）による許可ホストの設定を可能に
  - デフォルトの許可リストに `antigravity.google` を追加

### ドキュメント

- `docs/architecture.md` 新規作成: review platform における mcp-gateway の役割（MCP reverse proxy / routing gateway / auth boundary）を明文化し、thread-owl / mcp-resource-subscriber / review-raven / Mcp-Docker との責務境界を記載（[#92](https://github.com/scottlz0310/mcp-gateway/issues/92)）
- `README.md`: Repository Stack 表を5本立てレビュー基盤の全コンポーネントに拡張（[#92](https://github.com/scottlz0310/mcp-gateway/issues/92)）
- `docs/spike-105-auth-issue-investigation.md`: ルーティング先 MCP サーバーで発生する認証切れ（401エラー）に関する調査結果・根本原因分析レポートを追加（[#105](https://github.com/scottlz0310/mcp-gateway/issues/105)）

## [0.5.2] - 2026-06-10

### 修正

- `ci.yml`: main push で `:latest` が更新されないよう `type=raw,value=latest,enable={{is_default_branch}}` を削除（`:main` + `:sha-*` のみ発行）（[#93](https://github.com/scottlz0310/mcp-gateway/issues/93)）
- `release.yml`: prerelease タグでも `:latest` が付く問題を修正。`type=raw,value=latest` を削除し `latest=auto`（デフォルト）に委ねることで非 prerelease semver タグにのみ `:latest` を付与（[#93](https://github.com/scottlz0310/mcp-gateway/issues/93)）

### ドキュメント

- `CONTRIBUTING.md` を新規作成し、prerelease タグは semver pre-release 形式（`-` 含む）必須である旨を明記（[#94](https://github.com/scottlz0310/mcp-gateway/pull/94)）

## [0.5.1] - 2026-06-01

### 修正

- `parseRoutes` が値が空またはホワイトスペースのみの `ROUTE_*` 環境変数を
  エラーではなくスキップするよう修正（[#86](https://github.com/scottlz0310/mcp-gateway/pull/86)）。
  これにより docker-compose の条件付きパターン
  `ROUTE_FOO=${TOKEN:+/prefix|upstream|opts}` が機能するようになる。
  `TOKEN` が未設定の場合は空文字列に展開され、ルートは登録されずエラーにもならない。
  Mcp-Docker v2.12.0 と対になる修正。

### セキュリティ

- `golang.org/x/crypto` を v0.52.0 へ更新（[#85](https://github.com/scottlz0310/mcp-gateway/pull/85)）。

## [0.5.0] - 2026-05-18

### 追加

- `ROUTE_*` 環境変数に `upstream_bearer_token_env` オプションを追加
  （[#82](https://github.com/scottlz0310/mcp-gateway/pull/82)）。
  mcp-gateway が upstream MCP サーバへ送る `Authorization: Bearer` ヘッダを
  環境変数から読み込んだ固定 API トークンに切り替えられるようになった。
  - 設定時、upstream はクライアントの OAuth context token の代わりに env-var トークンを受け取る。
  - Fail-closed: 起動時に指定した env var が未設定・空の場合はエラー終了。
  - 401 分離: `upstream_bearer_token_env` 設定済みルートで upstream が 401 を返しても
    クライアントの OAuth キャッシュを無効化しない。
  - シークレット保護: Bearer token の値はログに書き込まれない。
  - リクエスト毎再読み込み: `os.Getenv` を毎回実行するため、コンテナ再起動なしで
    シークレットローテーション可能。

## [0.4.0] - 2026-05-18

### 追加

- 汎用 OAuth 環境変数を追加し、設定を GitHub 固有の命名から分離（[#5](https://github.com/scottlz0310/mcp-gateway/issues/5)）
  - 新しい canonical 変数: `OAUTH_PROVIDER`（デフォルト `github`）、`OAUTH_CLIENT_ID`、`OAUTH_CLIENT_SECRET`、`OAUTH_SCOPES`
  - `OAUTH_PROVIDER` は provider factory に渡され、将来の非 GitHub provider (#6) に備える
  - 移行マップ:

    | 新 | 旧（deprecated） |
    |---|---|
    | `OAUTH_PROVIDER` | _(新規; デフォルト `github`)_ |
    | `OAUTH_CLIENT_ID` | `GITHUB_MCP_CLIENT_ID` |
    | `OAUTH_CLIENT_SECRET` | `GITHUB_MCP_CLIENT_SECRET` |
    | `OAUTH_SCOPES` | `GITHUB_MCP_OAUTH_SCOPES` |
- 期限付き GitHub OAuth user access token の透過的ローテーション（[#70](https://github.com/scottlz0310/mcp-gateway/issues/70), Phase A）
  - `MCP_GATEWAY_GITHUB_REFRESH_ENABLED` / `gateway.github_refresh_enabled` フラグで rotation を有効化（デフォルト `false`）
  - upstream provider が `refresh_token` と `expires_in` を返す場合、access token 期限の約 5 分前に refresh token を用いて自動ローテーションし、新 token を upstream MCP server に透過的に転送する
  - rotation は best-effort: provider 失敗時は `rotation_failed` をログ出力し、既存の 401 → 再認証フローへフォールバック
  - Provider インターフェース（`internal/auth/provider`）に正規化された `TokenResponse` と `RefreshToken` メソッドを追加
- バックグラウンド処理向け委任アクセス PoC（[#72](https://github.com/scottlz0310/mcp-gateway/issues/72), Phase B）
  - loopback 専用の内部 API `POST /internal/v1/whoami` を追加。指定 subject の最新有効 access token を返し、期限間近なら gateway 側で透過的にローテーションする
  - `MCP_GATEWAY_INTERNAL_SECRET`（32 文字以上）と `MCP_GATEWAY_INTERNAL_PORT` の両方が設定されたときのみ起動する fail-closed 設計。未設定時は API を提供せず、その旨をログ出力する。API 内部の透過的ローテーションには Phase A の `MCP_GATEWAY_GITHUB_REFRESH_ENABLED=true` も必要。未有効時はキャッシュ済みトークンを返すのみでローテーションは行わない
  - listener は `127.0.0.1` にのみ bind し、共有 Bearer secret は定数時間比較で検証。リクエストボディ上限 4KB、未知の JSON フィールドは拒否
  - レスポンスは `{access_token, token_type, expires_at, scopes}`（refresh token は返さない）。エラーは `404 subject_not_found`、`401 invalid_authorization`、`403 loopback_required`、`400 invalid_body`/`missing_subject`、`405 method_not_allowed`（`Allow: POST` ヘッダ付き）、`502 upstream_failure`、`502 rotation_failed`（キャッシュ済みトークンが GitHub refresh leeway 内だがローテーションで新しいトークンを得られなかった場合）
  - 想定利用者: upstream MCP server の長寿命バックグラウンド処理（例: `copilot-review-mcp` の watch goroutine）が、通常の MCP リクエスト経路の外で新しい access token を取得するケース。設計とセキュリティモデルは `docs/spike-72-delegated-background-access.md` 参照

### 変更

- OAuth 環境変数の読み込み優先順位を整理: `OAUTH_*` が旧 `GITHUB_MCP_*` より優先される。旧変数のみ設定されている場合は採用するが、process 内で 1 回だけ deprecation 警告を出力する。両方設定されている場合は canonical を採用し旧値は無視（警告あり）。旧名は将来のメジャーリリースで削除予定。YAML 設定キー（`auth.github_client_id`、`auth.github_client_secret`、`gateway.oauth_scopes`）は変更しない（[#5](https://github.com/scottlz0310/mcp-gateway/issues/5)）。
- `auth.Handler.ValidateToken` がローテーション後の access token を subject と同時に返すよう拡張し、middleware が request context のトークンを差し替えられるようにした。内部 API のみで公開 surface には影響なし。
## [0.3.0] - 2026-05-07

### 追加

- HTTP request logging middleware と `slog` フィールド標準化（[#42](https://github.com/scottlz0310/mcp-gateway/issues/42), [PR #47](https://github.com/scottlz0310/mcp-gateway/pull/47)）
  - 各 request で `method`、`path`、`status`、`latency_ms`、`remote_addr` を含む `"http request"` 構造化ログを出力
  - auth、proxy、setup、startup 周辺の主要イベントを `log/slog` に統一
- `MCP_GATEWAY_PUBLIC_URL` / `gateway.public_url` と `MCP_GATEWAY_BIND_ADDR` / `gateway.bind_addr`（[#48](https://github.com/scottlz0310/mcp-gateway/issues/48), [PR #51](https://github.com/scottlz0310/mcp-gateway/pull/51)）
  - OAuth/discovery/PRM 用の公開 URL と HTTP listener address を分離
- ルート単位の Protected Resource Metadata（MCP Authorization Spec 2025-06-18, RFC 9728 §3.1）（[#49](https://github.com/scottlz0310/mcp-gateway/issues/49), [PR #58](https://github.com/scottlz0310/mcp-gateway/pull/58)）
  - 認証付き non-root route で `GET /.well-known/oauth-protected-resource/<prefix>` を公開し、route-scoped `resource` を返す
  - 401 応答の `WWW-Authenticate.resource_metadata` は利用可能な場合 route-scoped PRM を指す
  - root-prefix route は後方互換のため gateway-wide PRM を継続利用
- 信頼済み reverse proxy header 対応（[#56](https://github.com/scottlz0310/mcp-gateway/issues/56), [PR #59](https://github.com/scottlz0310/mcp-gateway/pull/59)）
  - `MCP_GATEWAY_TRUSTED_PROXIES` / `gateway.trusted_proxies` で immediate reverse proxy の CIDR allowlist を指定可能
  - 信頼済み peer からの `X-Forwarded-Proto`、`X-Forwarded-Host`、`X-Forwarded-For` のみを反映し、未信頼 forwarded headers は削除
  - 不正な trusted proxy CIDR は起動時エラーとして扱う
- RFC 8707 `resource` パラメータと token audience tracking（[#57](https://github.com/scottlz0310/mcp-gateway/issues/57), [PR #60](https://github.com/scottlz0310/mcp-gateway/pull/60)）
  - `/authorize`、`/device_authorization`、`grant_type=refresh_token` で `resource` を受け付ける
  - discovery metadata に `resource_parameter_supported: true` を追加
  - `grant_type=refresh_token` は元 audience の維持または sub-path への narrowing を許可し、拡大・別 route への変更は `invalid_target` で拒否

### 変更

- デフォルト bind address を全 interface（`:<port>`）から loopback-only（`127.0.0.1:8080`）へ変更。Docker deployment では `MCP_GATEWAY_BIND_ADDR=0.0.0.0:8080` を設定する。
- デフォルト public URL を `http://localhost:8080` から `http://127.0.0.1:8080` へ変更。
- example Compose 設定を `bind_addr` / `public_url` 分離に合わせて更新（[PR #52](https://github.com/scottlz0310/mcp-gateway/pull/52)）。
- CI pipeline 強化（[#43](https://github.com/scottlz0310/mcp-gateway/issues/43), [PR #62](https://github.com/scottlz0310/mcp-gateway/pull/62)）
  - `govulncheck` を追加し、Docker build が vulnerability scan に依存するよう変更
  - 明示的な `.golangci.yml` linter 設定を追加
  - golangci-lint tooling を pin し、Codecov patch target を 75% に引き上げ
- Go dependency と GitHub Actions の maintenance 更新（[PR #66](https://github.com/scottlz0310/mcp-gateway/pull/66), [PR #67](https://github.com/scottlz0310/mcp-gateway/pull/67)）。

### 修正

- route-scoped resource に対して ancestor-scoped token を受け入れるよう audience validation を修正（[#61](https://github.com/scottlz0310/mcp-gateway/issues/61), [PR #63](https://github.com/scottlz0310/mcp-gateway/pull/63)）
  - `public_url` で gateway-wide token を取得した client が複数の authenticated sub-route を初期化する場合の `token audience mismatch` 401 を解消
  - sibling route、narrower-recorded-vs-broader-requested、同一 prefix 風の別 segment は引き続き拒否

### ドキュメント

- 運用・設定ドキュメントの再構成（[#44](https://github.com/scottlz0310/mcp-gateway/issues/44), [PR #64](https://github.com/scottlz0310/mcp-gateway/pull/64)）
  - root README を Getting Started 優先の構成に整理
  - `docs/configuration.md` に環境変数、`config.yaml`、route、token persistence、reverse proxy、endpoint reference を集約
  - `docs/operations.md` に起動停止、health check、構造化ログフィールド、troubleshooting、migration notes を追加
  - `docs/README.md` を追加し、guide、runbook、example、spike note への入口を整理

### 非推奨

- `MCP_GATEWAY_BASE_URL` / `gateway.base_url` は `MCP_GATEWAY_PUBLIC_URL` / `gateway.public_url` に置き換え。deprecated setting 検出時は起動時 warning を出力し、将来リリースで削除予定。

### 移行ガイド

- Docker Compose users は container port forwarding 継続のため `MCP_GATEWAY_BIND_ADDR=0.0.0.0:<port>` を追加してください。`MCP_GATEWAY_PUBLIC_URL` は browser / OAuth client から見える URL に維持します。
- TLS を mcp-gateway の手前で終端する場合は、`MCP_GATEWAY_PUBLIC_URL` / `gateway.public_url` を外部 origin に設定し、immediate proxy peer を `MCP_GATEWAY_TRUSTED_PROXIES` / `gateway.trusted_proxies` に設定してください。
- `MCP_GATEWAY_TOKEN_AUDIENCE_STRICT=true`（または `token_audience_strict: true`）は、すべての active token が audience metadata を持つようになってから有効化してください。strict mode 前に `"token without audience accepted during grace period"` ログを監視してください。

### ロードマップ

- マルチ audience token（1 つの opaque token に複数の `aud` 値、例: `["https://gw.example/mcp/a", "https://gw.example/mcp/b"]`）は将来候補として記録し、現リリースには含めない。

## [0.2.0] - 2026-05-05

### Added

- 初回起動セットアップウィザード ([#12](https://github.com/scottlz0310/mcp-gateway/issues/12))
  - `GITHUB_MCP_CLIENT_ID` / `GITHUB_MCP_CLIENT_SECRET` / routes のいずれかが起動時に不足している場合、gateway は終了せず**セットアップモード**に自動遷移する
  - `GET /setup?token=<TOKEN>` は不足している設定項目のリストを JSON で返す
  - `POST /setup?token=<TOKEN>` は `{client_id, client_secret, routes[]}` を受け取り、secret を `age` で暗号化して `config.yaml` に書き込み、終了コード `0` でプロセスを終了する（supervisor による再起動を想定）
  - セットアップ token は 16 bytes / 32 hex chars、シングルユース、TTL 15 分
  - セットアップモード中、`/setup` 以外のすべてのパスは `503 {"error":"setup_required","setup_url":"..."}` を返す
  - `internal/setup` パッケージ: `Manager`（token ライフサイクル）、`IsSetupRequired`（実効設定の充足判定）、`Handler`（GET/POST エンドポイント）、`UnconfiguredHandler`（503 フォールバック）
  - `AppConfig` に `Routes []RouteConfig` と `Setup SetupConfig` フィールドを追加（YAML キー: `routes:`、`setup:`）
  - `router.ParseFromConfig` を追加: `[]config.RouteConfig` → `[]Route` を `ParseEnv` と同じバリデーションで変換（env `ROUTE_*` が優先、config.yaml routes はフォールバック）
  - 通常起動時、`ROUTE_*` env vars が未設定なら `config.yaml` の routes にフォールバックする

- `filippo.io/age` X25519 によるシークレット暗号化保存 ([#11](https://github.com/scottlz0310/mcp-gateway/issues/11))
  - `GITHUB_MCP_CLIENT_SECRET` を `config.yaml` に `ENC[age:]<base64>` 形式で保存可能（環境変数のみに頼らない構成へ）
  - `internal/config` パッケージ: `LoadKey` / `EncryptField` / `DecryptField` / `MigrateSecret` / `LoadConfig` / `SaveConfig`
  - キーファイル（`gateway.key`）は標準 `age-keygen` identity 形式（`AGE-SECRET-KEY-1...`）で保存し、`age` CLI と互換
  - キー生成優先順位: 既存 `gateway.key` > `MCP_GATEWAY_MASTER_KEY` からの HKDF-SHA256 決定論的導出 > ランダム生成
  - 起動時の自動マイグレーション: config に `ENC[age:]` → 復号; 平文が config にある → 暗号化して書き戻し; `GITHUB_MCP_CLIENT_SECRET` env のみ → 暗号化して config に保存; どちらも無い → 起動失敗
  - 破損・空・読み取り不能な `gateway.key` は自動再生成せず即時起動失敗（暗号化済みシークレットの恒久喪失を防ぐ）
  - `MCP_GATEWAY_MASTER_KEY` は最低 32 bytes 必須、`MCP_MASTER_KEY` は legacy alias として受け付ける
  - キー内容・平文 secret・`ENC[...]` 暗号文・env var の値は一切ログに書き込まれない

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

[Unreleased]: https://github.com/scottlz0310/mcp-gateway/compare/v0.9.0...HEAD
[0.9.0]: https://github.com/scottlz0310/mcp-gateway/compare/v0.8.0...v0.9.0
[0.8.0]: https://github.com/scottlz0310/mcp-gateway/compare/v0.7.0...v0.8.0
[0.7.0]: https://github.com/scottlz0310/mcp-gateway/compare/v0.6.0...v0.7.0
[0.6.0]: https://github.com/scottlz0310/mcp-gateway/compare/v0.5.2...v0.6.0
[0.5.2]: https://github.com/scottlz0310/mcp-gateway/compare/v0.5.1...v0.5.2
[0.5.1]: https://github.com/scottlz0310/mcp-gateway/compare/v0.5.0...v0.5.1
[0.5.0]: https://github.com/scottlz0310/mcp-gateway/compare/v0.4.0...v0.5.0
[0.4.0]: https://github.com/scottlz0310/mcp-gateway/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/scottlz0310/mcp-gateway/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/scottlz0310/mcp-gateway/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/scottlz0310/mcp-gateway/releases/tag/v0.1.0
