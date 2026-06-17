# Changelog

すべての変更は [Keep a Changelog](https://keepachangelog.com/ja/1.1.0/) に従い、
バージョニングは [Semantic Versioning](https://semver.org/lang/ja/) に従う。

## [Unreleased]

### 追加

- 実行時状態ファイルのデフォルトパスを OS のユーザーデータディレクトリに変更（[#144](https://github.com/scottlz0310/mcp-gateway/issues/144)）
  - `MCP_GATEWAY_KEY_PATH`・`MCP_CONFIG_FILE`・`MCP_GATEWAY_TOKEN_STORE_PATH` のデフォルトがプロセスのカレントディレクトリや Docker 専用の `/data/` から OS ユーザー状態ディレクトリ（Windows: `%LOCALAPPDATA%\mcp-gateway\`、Linux: `~/.local/share/mcp-gateway/`、macOS: `~/Library/Application Support/mcp-gateway/`）に変更
  - Docker 環境では引き続き環境変数で上書きするため影響なし。変更が適用されるのは非コンテナ環境のみ
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

[Unreleased]: https://github.com/scottlz0310/mcp-gateway/compare/v0.5.2...HEAD
[0.5.2]: https://github.com/scottlz0310/mcp-gateway/compare/v0.5.1...v0.5.2
[0.5.1]: https://github.com/scottlz0310/mcp-gateway/compare/v0.5.0...v0.5.1
[0.5.0]: https://github.com/scottlz0310/mcp-gateway/compare/v0.4.0...v0.5.0
[0.4.0]: https://github.com/scottlz0310/mcp-gateway/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/scottlz0310/mcp-gateway/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/scottlz0310/mcp-gateway/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/scottlz0310/mcp-gateway/releases/tag/v0.1.0
