# 設定リファレンス

このページは mcp-gateway の詳細な設定リファレンスです。README は初回起動手順とこのドキュメントへのリンクのみを掲載しています。

## 起動に必要な入力

mcp-gateway を通常モードで起動するには、以下のすべてが揃っている必要があります。

| 必須項目 | 環境変数 | `config.yaml` |
|---------|----------|---------------|
| OAuth クライアント ID | `OAUTH_CLIENT_ID`（旧: `GITHUB_MCP_CLIENT_ID`） | `auth.github_client_id` |
| OAuth クライアントシークレット | `OAUTH_CLIENT_SECRET`（初回起動時シード用、旧: `GITHUB_MCP_CLIENT_SECRET`） | `auth.github_client_secret` |
| 1つ以上のルート | `ROUTE_<NAME>` | `routes:` |

いずれかの必須値が欠けている場合、ゲートウェイはセットアップモードに入り、ワンタイム `/setup` URL を stdout に出力します。

## 優先順位

設定は以下の順序で解決されます。

| 設定 | 優先順位 |
|------|---------|
| OAuth プロバイダー | `OAUTH_PROVIDER` > `auth.provider` > `github`（デフォルト） |
| OAuth クライアント ID | `OAUTH_CLIENT_ID` > 非推奨 `GITHUB_MCP_CLIENT_ID` > `auth.client_id` > `auth.github_client_id` |
| OAuth クライアントシークレット | 暗号化/平文 `auth.client_secret` > 暗号化/平文 `auth.github_client_secret` > 非空 `OAUTH_CLIENT_SECRET` > 非推奨 `GITHUB_MCP_CLIENT_SECRET`（`config.yaml` シード用） |
| ルート | `ROUTE_<NAME>` 環境変数 > `config.yaml` の `routes:` > 非推奨 `GITHUB_MCP_UPSTREAM_URL` フォールバック |
| 公開 URL | `MCP_GATEWAY_PUBLIC_URL` > 非推奨 `MCP_GATEWAY_BASE_URL` > `gateway.public_url` > 非推奨 `gateway.base_url` > デフォルト |
| バインドアドレス | `MCP_GATEWAY_BIND_ADDR` > `gateway.bind_addr` > `127.0.0.1:<解決済みポート>` |
| OAuth スコープ | `OAUTH_SCOPES` > 非推奨 `GITHUB_MCP_OAUTH_SCOPES` > `gateway.oauth_scopes` > `repo,user` |
| 信頼済みプロキシ | `MCP_GATEWAY_TRUSTED_PROXIES` > `gateway.trusted_proxies` > なし |
| トークン audience 厳格モード | `MCP_GATEWAY_TOKEN_AUDIENCE_STRICT` > `gateway.token_audience_strict` > `false` |
| GitHub リフレッシュトークンローテーション | `MCP_GATEWAY_GITHUB_REFRESH_ENABLED` > `gateway.github_refresh_enabled` > `false` |
| GitHub App ID | `GITHUB_APP_ID` > `github_app.app_id` |
| GitHub App installation ID | `GITHUB_APP_INSTALLATION_ID` > `github_app.installation_id` |
| GitHub App private key | 暗号化/平文 `github_app.private_key` > `GITHUB_APP_PRIVATE_KEY` > `GITHUB_APP_PRIVATE_KEY_PATH` |
| 許可リダイレクトホスト | `MCP_GATEWAY_ALLOWED_REDIRECT_HOSTS` > `gateway.allowed_redirect_hosts` > `localhost, 127.0.0.1, vscode.dev, antigravity.google`（デフォルト） |
| 許可リダイレクトスキーム | `MCP_GATEWAY_ALLOWED_REDIRECT_SCHEMES` > `gateway.allowed_redirect_schemes` > `antigravity, antigravity-insiders`（デフォルト） |

OAuth クライアントシークレットは意図的に特別扱いです。`config.yaml` にシークレットが含まれると、`OAUTH_CLIENT_SECRET` / `GITHUB_MCP_CLIENT_SECRET` は初回起動シード時を除いて無視されます。

起動時に旧 `GITHUB_MCP_*` 変数を検出した場合、ゲートウェイは変数ごとに1回 `slog.Warn` を出力します。正規の `OAUTH_*` と旧変数が両方設定されている場合は正規が優先され、旧変数が無視された旨の警告がログに記録されます。

## 環境変数

| 変数 | デフォルト | 説明 |
|------|-----------|------|
| `OAUTH_PROVIDER` | `github` | OAuth プロバイダー種別。現在 `github` と `oidc` をサポート。 |
| `OAUTH_CLIENT_ID` | なし | OAuth クライアント ID。`auth.client_id` または `auth.github_client_id` が設定されていない場合は必須。`GITHUB_MCP_CLIENT_ID` を上書き。 |
| `OAUTH_CLIENT_SECRET` | なし | OAuth クライアントシークレット。設定シークレットが存在しない場合に暗号化 `config.yaml` のシードに使用。`GITHUB_MCP_CLIENT_SECRET` を上書き。 |
| `OAUTH_SCOPES` | `repo,user` | ゲートウェイが要求する OAuth スコープ。`GITHUB_MCP_OAUTH_SCOPES` を上書き。 |
| `OAUTH_ISSUER_URL` | なし | OIDC issuer URL（`OAUTH_PROVIDER=oidc` の場合は必須）。 |
| `OAUTH_AUDIENCE` | なし | OIDC audience（`OAUTH_PROVIDER=oidc` の場合はオプション）。将来のローカル JWT 検証用に予約済み。現在は UserInfo 検証で未使用/no-op。 |
| `GITHUB_MCP_CLIENT_ID` | なし | **非推奨** — `OAUTH_CLIENT_ID` を使用してください。起動時警告付きで引き続き受け入れ。 |
| `GITHUB_MCP_CLIENT_SECRET` | なし | **非推奨** — `OAUTH_CLIENT_SECRET` を使用してください。起動時警告付きで引き続き受け入れ。 |
| `GITHUB_MCP_OAUTH_SCOPES` | なし | **非推奨** — `OAUTH_SCOPES` を使用してください。起動時警告付きで引き続き受け入れ。 |
| `GITHUB_APP_ID` | なし | `upstream_github_app=true` ルートがJWTの `iss` に使用する正の整数GitHub App ID。caller OAuth のClient IDとは別の値。 |
| `GITHUB_APP_INSTALLATION_ID` | なし | installation token を発行する対象 installation の正の整数 ID。 |
| `GITHUB_APP_PRIVATE_KEY` | なし | GitHub App RSA private key の PEM。初回起動時に `ENC[age:]` へ暗号化して `config.yaml` に保存する。ログには出力しない。 |
| `GITHUB_APP_PRIVATE_KEY_PATH` | なし | PEM private key ファイルのパス。`GITHUB_APP_PRIVATE_KEY` が空の場合の初回シード。暗号化後の config があれば以後は不要。 |
| `GITHUB_API_URL` | `https://api.github.com` | installation token 発行先の GitHub API base URL。GitHub Enterprise Server では API URL を指定する。 |
| `ROUTE_<NAME>` | なし | `<prefix>\|<upstream_url>[|auth=none]` 形式のルート定義。`config.yaml` で設定されていない限り1つ以上必須。 |
| `MCP_CONFIG_FILE` | OS state dir¹ `/config.yaml` | 永続化 YAML 設定ファイルのパス。 |
| `MCP_GATEWAY_KEY_PATH` | OS state dir¹ `/gateway.key` | `auth.github_client_secret` の暗号化に使用する age X25519 identity のパス。 |
| `MCP_GATEWAY_MASTER_KEY` | なし | オプションの決定論的キーシード。例: `openssl rand -base64 32` で生成した 32バイト以上のランダム文字列。`gateway.key` 作成時のみ使用。 |
| `MCP_MASTER_KEY` | なし | `MCP_GATEWAY_MASTER_KEY` の旧エイリアス。 |
| `MCP_GATEWAY_PUBLIC_URL` | `http://127.0.0.1:<port>` | OAuth コールバック・ディスカバリメタデータ・Protected Resource Metadata で使用するクライアントから見える正規 URL。 |
| `MCP_GATEWAY_BIND_ADDR` | `127.0.0.1:<port>` | TCP リスナーアドレス。Docker でポートを公開する場合は `0.0.0.0:<port>` を使用。 |
| `MCP_GATEWAY_TLS_CERT_PATH` | なし | TLS サーバー証明書（PEM）のパス。`MCP_GATEWAY_TLS_KEY_PATH` とペアで設定すると HTTPS で listen する。片方のみの設定やファイル欠如は起動エラー（フェイルファスト）。 |
| `MCP_GATEWAY_TLS_KEY_PATH` | なし | TLS 秘密鍵（PEM）のパス。`MCP_GATEWAY_TLS_CERT_PATH` とペアで設定する。 |
| `MCP_GATEWAY_ENABLE_HTTP2` | `true` | TLS リスナーで HTTP/2（ALPN `h2`）を有効化する。影響を受ける旧クライアント向けに `false` を設定すると HTTP/1.1 のみに固定できる（[TLS 終端](#tls-終端ローカル-https)参照）。 |
| `MCP_GATEWAY_PORT` | `8080` | `public_url` と `bind_addr` のデフォルト導出に使用するポート。 |
| `MCP_GATEWAY_BASE_URL` | なし | `MCP_GATEWAY_PUBLIC_URL` の非推奨エイリアス。設定されると起動時警告を出力。 |
| `MCP_GATEWAY_TRUSTED_PROXIES` | なし | `X-Forwarded-*` ヘッダーを信頼する直前のリバースプロキシの CIDR リスト（カンマ区切り）。 |
| `MCP_GATEWAY_TOKEN_STORE_PATH` | OS state dir¹ `/tokens.json` | 永続トークンストアのベースパス。実データは `<パス>.refresh.db`（SQLite）に保存される（[トークン永続化](#トークン永続化)参照）。空値に設定すると永続化を無効化。Docker 環境は環境変数で上書き。 |
| `MCP_GATEWAY_AUTH_AUDIT_LOG_PATH` | OS audit dir² | OAuth 監査 JSON Lines の絶対 path。相対 path と Git worktree 配下は起動時に拒否される。 |
| `MCP_GATEWAY_AUTH_AUDIT_MAX_SIZE_MB` | `10` | 監査ログ 1 ファイルの最大サイズ（MiB）。 |
| `MCP_GATEWAY_AUTH_AUDIT_MAX_BACKUPS` | `5` | 保持するローテーション済み監査ログの最大数。 |
| `MCP_GATEWAY_AUTH_AUDIT_MAX_AGE_DAYS` | `30` | ローテーション済み監査ログの最大保持日数。 |
| `MCP_GATEWAY_TOKEN_AUDIENCE_STRICT` | `false` | audience メタデータが記録されていない旧トークンを拒否する。移行中は無効のままにしてください。 |
| `MCP_GATEWAY_GITHUB_REFRESH_ENABLED` | `false` | 期限切れ間近の GitHub ユーザーアクセストークンを透過的にローテーションする。GitHub App のトークン有効期限が無効でも安全に有効化できます（`refresh_token` と `expires_in` が返ってこない場合はローテーションパスが休眠状態になります）。[GitHub OAuth リフレッシュトークンローテーション](#github-oauth-リフレッシュトークンローテーション) を参照。 |
| `MCP_GATEWAY_ALLOWED_REDIRECT_HOSTS` | なし | OAuth redirect_uri で許可するホスト名のカンマ区切りリスト。設定するとビルトインデフォルトリストを完全に置き換えます。 |
| `MCP_GATEWAY_ALLOWED_REDIRECT_SCHEMES` | なし | `http`・`https` に加えて OAuth redirect_uri で許可するカスタム URL スキーム（RFC 8252）のカンマ区切りリスト。設定するとビルトインデフォルトリストを完全に置き換えます。デフォルト: `antigravity,antigravity-insiders`。 |
| `LOG_LEVEL` | `info` | JSON ログレベル: `debug`、`info`、`warn`、`error`。 |
| `SESSION_TTL_MIN` | `10` | OAuth 認証セッションの有効期間（分）。 |
| `TOKEN_CACHE_TTL_MIN` | `30` | インメモリ検証キャッシュの TTL（分）。トークン永続化が無効な場合に使用。 |
| `TOKEN_EXPIRES_IN_SEC` | `7776000` | クライアントへの通知トークン有効期間と永続トークンエントリの TTL。デフォルトは 90 日。 |
| `GITHUB_MCP_UPSTREAM_URL` | なし | `ROUTE_*` も `routes:` エントリも存在しない場合の非推奨シングルアップストリームフォールバック。 |

¹ **OS state directory** — `gatewayStateDir()` が起動時に解決するディレクトリ:

| OS | デフォルト state ディレクトリ |
|----|---------------------------|
| Windows | `%LOCALAPPDATA%\mcp-gateway\` |
| macOS | `~/Library/Application Support/mcp-gateway/` |
| Linux / other | `$XDG_STATE_HOME/mcp-gateway/` → `~/.local/state/mcp-gateway/` |
| Docker（公式 image） | `/data/mcp-gateway/`（`XDG_STATE_HOME=/data` 経由） |

ディレクトリは起動時に自動作成されます（`MkdirAll 0700`）。Docker やコンテナ化された環境では必ず環境変数でパスを明示的に指定してください。OS デフォルトはベアメタルインストール専用です。

² **OS audit log directory** — `gatewayStateDir()` とは独立して `authaudit.defaultPath()` が解決するパス:

| OS | デフォルト監査ログパス |
|----|----------------------|
| Windows | `%LOCALAPPDATA%\mcp-gateway\logs\auth-audit.jsonl` |
| macOS | `~/Library/Logs/mcp-gateway/auth-audit.jsonl` |
| Linux / other | `$XDG_STATE_HOME/mcp-gateway/logs/auth-audit.jsonl` → `~/.local/state/mcp-gateway/logs/auth-audit.jsonl` |
| Docker（公式 image） | `/data/mcp-gateway/logs/auth-audit.jsonl`（`XDG_STATE_HOME=/data` 経由） |

`MCP_GATEWAY_MASTER_KEY` はホワイトスペース除去後の文字列バイト長で検証されます。`openssl rand -base64 32` で生成した base64 文字列はそのまま受け入れられます（ゲートウェイは検証前に base64 デコードしません）。

## `config.yaml`

例:

```yaml
auth:
  github_client_id: "Ov23liXXXX"
  github_client_secret: "ENC[age:]<base64-ciphertext>"

github_app:
  app_id: 123456
  installation_id: 12345678
  private_key: "ENC[age:]<base64-ciphertext>"

gateway:
  public_url: "http://127.0.0.1:8080"
  bind_addr: "127.0.0.1:8080"
  port: "8080"
  oauth_scopes: "repo,user"
  trusted_proxies:
    - "127.0.0.1/32"
  token_audience_strict: false
  allowed_redirect_hosts:
    - "antigravity.google"

routes:
  - name: github
    prefix: /mcp/github
    upstream: http://github-mcp:8082
    upstream_github_app: true
  - name: public
    prefix: /public
    upstream: http://public-svc:8083
    no_auth: true

setup:
  completed: true
```

### YAML キー

| キー | 説明 |
|------|------|
| `auth.provider` | OAuth プロバイダー種別（`github` または `oidc`）。 |
| `auth.client_id` | 汎用 OAuth クライアント ID。 |
| `auth.client_secret` | 汎用 OAuth クライアントシークレット。`ENC[age:]...` として暗号化可能。 |
| `auth.github_client_id` | GitHub App クライアント ID。 |
| `auth.github_client_secret` | GitHub App クライアントシークレット。`ENC[age:]...` として暗号化可能。 |
| `auth.oidc_issuer_url` | OIDC issuer URL。 |
| `auth.oidc_audience` | OIDC audience。将来のローカル JWT 検証用に予約済み。現在は UserInfo 検証で未使用/no-op。 |
| `github_app.app_id` | server-to-server installation token用の正の整数GitHub App ID。App JWTの `iss` に使用する。 |
| `github_app.installation_id` | token 発行対象の GitHub App installation ID。 |
| `github_app.private_key` | GitHub App RSA private key。`ENC[age:]...` として暗号化保存する。 |
| `gateway.public_url` | OAuth および MCP クライアントに見える正規公開 URL。 |
| `gateway.bind_addr` | TCP リスナーアドレス。 |
| `gateway.base_url` | `gateway.public_url` の非推奨エイリアス。 |
| `gateway.port` | デフォルト導出に使用するポート。 |
| `gateway.oauth_scopes` | GitHub に要求する OAuth スコープ。 |
| `gateway.trusted_proxies` | 信頼済みリバースプロキシの CIDR リスト。 |
| `gateway.token_audience_strict` | 旧トークンの audience 厳格強制。 |
| `gateway.github_refresh_enabled` | GitHub OAuth アクセストークンの透過的ローテーションを有効化。[GitHub OAuth リフレッシュトークンローテーション](#github-oauth-リフレッシュトークンローテーション) を参照。 |
| `gateway.allowed_redirect_hosts` | OAuth redirect_uri で許可するホスト名の YAML リスト。設定するとビルトインデフォルトリストを完全に置き換えます。 |
| `gateway.allowed_redirect_schemes` | `http`・`https` に加えて OAuth redirect_uri で許可するカスタム URL スキーム（RFC 8252）の YAML リスト。設定するとビルトインデフォルトリストを完全に置き換えます。デフォルト: `["antigravity", "antigravity-insiders"]`。 |
| `routes[].name` | ルート名。空でない必要があります。 |
| `routes[].prefix` | URL パスプレフィックス。`/` で始まる必要があります。末尾スラッシュは `/` を除いて除去されます。 |
| `routes[].upstream` | 絶対 `http` または `https` upstream URL。 |
| `routes[].no_auth` | `true` の場合、このルートの Bearer 検証をスキップします。`upstream_oauth` と同時設定不可。 |
| `routes[].upstream_bearer_token_env` | ゲートウェイ→upstream の Bearer トークンを取得する環境変数名。起動時に env var が未設定または空の場合は起動失敗（フェールクローズ）。`upstream_oauth` と排他。 |
| `routes[].required_audience` | アクセストークンの `aud` クレームに要求する値（デフォルト: `mcp-gateway`）。クライアントは `/token` に `resource=<name>` を渡してこの audience のトークンを取得する。 |
| `routes[].upstream_oauth` | Upstream OAuth 委任。`auto`（RFC 9728 + RFC 8414 で AS を自動検出）または絶対 issuer URL（`https://...`）。`upstream_bearer_token_env` および `no_auth` と排他。[Upstream OAuth 委任](#upstream-oauth-委任) を参照。 |
| `routes[].upstream_oauth_scope` | Upstream AS へのトークンリクエストで要求するスコープ（スペース区切り。カンマ区切りは自動正規化）。`upstream_oauth` が必要。 |
| `routes[].upstream_oauth_grant` | Upstream トークン取得に使用する OAuth 2.0 グラントタイプ（`authorization_code` または `client_credentials`、デフォルト: `authorization_code`）。`upstream_oauth` が必要。[Upstream OAuth 委任](#upstream-oauth-委任) を参照。 |
| `routes[].upstream_provider_token` | `true` の場合、ゲートウェイの provider アクセストークン（builtin モードでは GitHub ユーザートークン）を upstream Bearer トークンとして注入する。ゲートウェイ認証が必要（`no_auth` と排他）。`upstream_bearer_token_env` および `upstream_oauth` と排他。[プロバイダートークン委任](#プロバイダートークン委任) を参照。 |
| `routes[].upstream_github_app` | `true` の場合、GitHub App installation token を upstream Bearer トークンとして注入する。gateway 認証が必要で、他の upstream credential source と排他。[GitHub App installation token](#github-app-installation-token) を参照。 |
| `setup.completed` | ゲートウェイが書き込むセットアップウィザード状態。オペレーターが直接編集することは通常ありません。 |

ゲートウェイがシークレット移行またはセットアップ完了時に `config.yaml` を書き直す際、未知の YAML フィールドとコメントは保持されません。

## ルート設定

環境変数によるルート設定:

```bash
ROUTE_<NAME>=<prefix>|<upstream_url>[|option=value...]
```

例:

```bash
ROUTE_GITHUB=/mcp/github|http://github-mcp:8082
ROUTE_REVIEW_RAVEN=/mcp/review-raven|http://review-raven:8083
```

ルール:

- `NAME` は空でないこと。
- `prefix` は `/` で始まること。
- `prefix` にホワイトスペースを含まないこと。
- `upstream_url` は絶対 `http` または `https` URL であること。
- 重複プレフィックスは拒否されます。
- ルートは最長プレフィックス優先でソートされます。

### ルートオプション

パイプ区切りで追加指定できます。未知のオプションキーは起動時に拒否されます（フェールクローズ）。

| オプション | デフォルト | 説明 |
|-----------|----------|------|
| `auth` | `oauth` | `oauth`（Bearer 検証あり）または `none`（認証スキップ）。`upstream_oauth` と `none` は排他。 |
| `upstream_bearer_token_env` | なし | ゲートウェイ→upstream の Bearer トークンを取得する環境変数名。起動時に env var が未設定または空の場合は起動失敗（フェールクローズ）。`upstream_oauth` と排他。 |
| `required_audience` | `mcp-gateway` | アクセストークンに必要な `aud` クレーム値。クライアントは `/token` に `resource=<name>` を渡してこの audience のトークンを取得する。 |
| `upstream_oauth` | なし | Upstream OAuth 委任を有効化。`auto`（RFC 9728 + RFC 8414 で AS を自動検出）または絶対 issuer URL（`https://...`）。`upstream_bearer_token_env` と排他。[Upstream OAuth 委任](#upstream-oauth-委任) を参照。 |
| `upstream_oauth_scope` | なし | Upstream AS へのトークンリクエストで要求するスコープ（スペース区切り。カンマ区切りは自動正規化）。`upstream_oauth` が必要。 |
| `upstream_oauth_grant` | `authorization_code` | Upstream トークン取得に使用する OAuth 2.0 グラントタイプ。`authorization_code`（ユーザーを認可エンドポイントへリダイレクト）または `client_credentials`（バックグラウンドでトークンを取得、ユーザー操作不要）。`upstream_oauth` が必要。 |
| `upstream_provider_token` | `false` | `true` の場合、ゲートウェイの provider アクセストークン（builtin モードでは GitHub ユーザートークン）を upstream Bearer トークンとして注入する。ゲートウェイ認証必須（`auth=none` と排他）。`upstream_bearer_token_env` および `upstream_oauth` と排他。[プロバイダートークン委任](#プロバイダートークン委任) を参照。 |
| `upstream_github_app` | `false` | GitHub App installation token を gateway が取得・更新して upstream に注入する。`auth=none` と他の upstream credential source は併用不可。[GitHub App installation token](#github-app-installation-token) を参照。 |

### GitHub App installation token

`upstream_github_app=true` は、個人 PAT を使わず GitHub App installation として動作する server-to-server route 用です。

```bash
ROUTE_GITHUB=/mcp/github|http://github-mcp:8082|upstream_github_app=true
GITHUB_APP_ID=123456
GITHUB_APP_INSTALLATION_ID=12345678
GITHUB_APP_PRIVATE_KEY_PATH=/run/secrets/github-app-private-key.pem
```

ゲートウェイは RSA private key で有効期間9分の App JWT を署名し、対象 installation の access token を取得します。installation token はメモリ内だけに保持し、期限5分前に更新します。upstream が 401 を返した場合は token を強制再発行し、body が再送可能なリクエストに限り1回だけ透過的に再試行します。

起動時には App ID・Installation ID・private key をすべて検証し、不足・不正があれば fail-closed で起動を中止します。private key は初回シード時に `ENC[age:]` へ移行され、token・JWT・private key の生値はログへ出力しません。

`MCP_GATEWAY_INTERNAL_SECRET` / `MCP_GATEWAY_INTERNAL_PORT` を設定した環境では、loopback-only の `GET /internal/v1/credentials` が route ごとの `credential_type`・installation ID・有効期限・ready 状態を返します。token 値は返しません。

### Upstream OAuth 委任

`upstream_oauth` を設定したルートでは、ゲートウェイが以下を自動実行します。

1. **Discovery + DCR**（初回アクセス時のみ）: upstream AS のメタデータを検出し、Dynamic Client Registration（RFC 7591）でクライアントを登録。登録情報は `{state-dir}/upstream_clients.json` にキャッシュ。
2. **トークン取得**: `upstream_oauth_grant` で指定されたフローでトークンを取得。
3. **トークン注入**: `Authorization: Bearer <upstream-token>` として upstream リクエストに付与。
4. **リフレッシュ**: トークン期限切れ前にプロアクティブにリフレッシュ、または upstream からの 401 レスポンス時に透過的にリフレッシュして再試行。

#### `authorization_code` フロー（デフォルト）

ユーザーを upstream AS の認可エンドポイントへリダイレクトします（PKCE あり）。初回アクセス時にユーザーの同意が必要です。取得したトークンはユーザーごとに `{state-dir}/upstream_tokens.json` へ保存されます。

```bash
ROUTE_SVC=/mcp/svc|https://svc.example.com/mcp|upstream_oauth=auto|upstream_oauth_scope=read write
```

`config.yaml` の場合:

```yaml
routes:
  - name: svc
    prefix: /mcp/svc
    upstream: https://svc.example.com/mcp
    upstream_oauth: auto
    upstream_oauth_scope: read write
    # upstream_oauth_grant は省略時 authorization_code がデフォルト
```

#### `client_credentials` フロー

ユーザー操作なしでバックグラウンドにトークンを取得します（サービス間通信向け）。upstream AS が `client_credentials` グラントをサポートしている必要があります。

```bash
ROUTE_SVC=/mcp/svc|https://svc.example.com/mcp|upstream_oauth=auto|upstream_oauth_grant=client_credentials|upstream_oauth_scope=api:read
```

`config.yaml` の場合:

```yaml
routes:
  - name: svc
    prefix: /mcp/svc
    upstream: https://svc.example.com/mcp
    upstream_oauth: auto
    upstream_oauth_grant: client_credentials
    upstream_oauth_scope: api:read
```

> **Note**: コールバックエンドポイント `GET /upstream/callback/{routeName}` は `authorization_code` フローの redirect_uri として自動登録されます。`client_credentials` フローでは使用されません。

### プロバイダートークン委任

`upstream_provider_token=true` を設定したルートでは、ゲートウェイが以下を自動実行します。

1. **トークン解決**: `EnsureFreshAccessTokenForSubject` を使って認証済み subject の provider アクセストークンを取得（`builtin` モードでは GitHub ユーザートークン）。
2. **注入**: 解決したトークンを upstream への `Authorization: Bearer` ヘッダーとして設定。gateway-signed JWT は upstream に転送されない。
3. **フェールクローズ**: subject が未キャッシュ・トークン失効・rotation 失敗のいずれかで解決不可の場合は 401 を返し、`WWW-Authenticate` ヘッダーで再認証を案内する。

**セキュリティ境界**:
- opt-in したルート（`upstream_provider_token=true`）のみに provider トークンが転送される。
- opt-in していないルート（thread-owl、playwright 等）には provider トークンが漏洩しない。
- `upstream_oauth`（upstream MCP サーバー固有の OAuth フロー）とは独立した概念である。

**設定例**（環境変数）:

```bash
ROUTE_REVIEW_RAVEN=/mcp/review-raven|http://review-raven:8083|upstream_provider_token=true
```

**設定例**（config.yaml）:

```yaml
routes:
  - name: review-raven
    prefix: /mcp/review-raven
    upstream: http://review-raven:8083
    upstream_provider_token: true
```

> **Note**: `upstream_provider_token=true` は `OAUTH_PROVIDER=builtin` の場合に最も効果を発揮します。
> `github` provider モードでは context トークン自体が GitHub トークンですが、
> `upstream_provider_token` を使うことで明示的なトークン解決・rotation・フェールクローズが有効になります。

## シークレット暗号化

ゲートウェイは `auth.github_client_secret` を `filippo.io/age` X25519 で暗号化して保存します。

起動時の動作:

1. `MCP_GATEWAY_KEY_PATH` から `gateway.key` をロードまたは生成する。
2. `MCP_CONFIG_FILE` から `config.yaml` をロードする。
3. シークレットを解決する:
   - config に `ENC[age:]...`: 復号して使用。
   - config に平文: 暗号化・config 書き直し・使用。
   - config シークレットなし + `OAUTH_CLIENT_SECRET`（または旧 `GITHUB_MCP_CLIENT_SECRET`）: 暗号化・config 保存・使用。
   - ソースなし: 起動失敗。

キー生成の優先順位:

| 条件 | 結果 |
|------|------|
| `gateway.key` が存在する | ロードして使用。`MCP_GATEWAY_MASTER_KEY` は無視。 |
| `gateway.key` が存在せず `MCP_GATEWAY_MASTER_KEY` が設定されている | HKDF-SHA256 で X25519 identity を導出して保存。 |
| `gateway.key` が存在せずマスターキーもない | ランダムな X25519 identity を生成して保存。 |

シークレットとキーマテリアルはログに出力されません。破損・空・読み取り不可の `gateway.key` は致命的エラーになります。自動再生成はされません。

## トークン永続化

デフォルトでは、検証済みトークン状態は `{state-dir}/tokens.json.refresh.db`（SQLite、WAL モード）に保存されます（`{state-dir}` は上記[環境変数](#環境変数)セクションの OS state directory テーブルを参照）。Docker 環境は `docker-compose.yml` の `MCP_GATEWAY_TOKEN_STORE_PATH` で上書きします。明示的なパスを指定する場合:

```bash
MCP_GATEWAY_TOKEN_STORE_PATH=/var/lib/mcp-gateway/tokens.json
```

`MCP_GATEWAY_TOKEN_STORE_PATH` はベースパスであり、実データは `<パス>.refresh.db` に保存されます。アクセストークンストアとリフレッシュトークンストアは同一 SQLite データベースを共有し、単一のファイル・単一のトランザクション境界で管理されます。ファイル名の `.refresh` はリフレッシュトークンストアだけが SQLite だった時期の歴史的経緯によるもので、現在は全トークン状態を保持します（旧バージョンへのロールバック時にも同じパスが参照できるよう維持されています）。

永続化を無効にするには空値に設定します:

```bash
MCP_GATEWAY_TOKEN_STORE_PATH=
```

プライマリトークンストアの動作:

- 認証成功後にトークンと identity のマッピングを保存。フィールド更新は単一の `UPDATE` 文で原子的に行われる。
- 毎分、期限切れエントリをスイープ（インデックス付き `DELETE`）。
- サポートされる環境ではモード `0600` で書き込み。
- SHA-256 でハッシュ化したトークンキーを保存(生トークン値は保存しない)。

旧バージョンからのマイグレーション: 旧 file-backed ストア（`tokens.json` および `tokens.json.refresh`）が存在する場合、初回起動時に内容を SQLite データベースへインポートし、元ファイルを `<元パス>.migrated` にリネームします。マイグレーションに失敗した場合は元ファイルを残したまま起動を中止します。

リフレッシュトークンストアは、ハッシュ化されたリフレッシュトークンキーと対応するアクセストークン値を平文で保存します（ゲートウェイがリフレッシュ時に GitHub へアクセストークンを再提示する必要があるため）。機密データとして扱ってください。

`MCP_GATEWAY_GITHUB_REFRESH_ENABLED=true`（または `gateway.github_refresh_enabled: true`）の場合、ゲートウェイは GitHub OAuth **リフレッシュトークン**をプライマリトークンストアにも保存します。再起動をまたいでローテーションを継続するためです。リフレッシュトークンは GitHub の `/login/oauth/access_token` エンドポイントへの再送が必要なため平文で書き込まれます。

リフレッシュトークン永続化の運用上の注意:

- トークンデータベースの読者はリフレッシュトークンの有効期間中、ログイン済みユーザーの GitHub セッションを乗っ取れます。GitHub の expiring-user-token 設定では通常**6ヶ月**（ユーザーが認可を取り消すか GitHub App が再設定されるまで）。
- バックアップも同じリスクを持ちます。バックアップボリュームを保存時暗号化するか、広いバックアップスコープから `tokens.json.refresh.db`（および SQLite の付随ファイル `-wal` / `-shm`、マイグレーション済みの `*.migrated`）を除外してください。
- コンテナイメージやスナップショットにいずれのファイルも含めないこと。
- 再起動をまたいだローテーションが不要な場合は `github_refresh_enabled` を無効にしてください。リフレッシュトークンはディスクに書き込まれません。

**builtin mode（`OAUTH_PROVIDER=builtin`）の追加事項:** builtin mode ではクライアントに渡すアクセストークンはゲートウェイ署名の JWT であり、GitHub アクセストークン自体ではありません。ただし Phase B delegated access（`EnsureFreshAccessTokenForSubject`、`upstream_provider_token=true` ルートおよび `/internal/v1/whoami` が使用）が upstream サービスへ GitHub トークンを引き渡せるようにするため、GitHub アクセストークンは JWT に紐付けて、アクセストークンストアとリフレッシュトークンストアの両方（同一 SQLite データベース内）に**平文で常に**保存されます（`github_refresh_enabled` 無効時でも同様）。`github_refresh_enabled` はリフレッシュトークン自体の保存有無のみを制御し、GitHub アクセストークンの保存有無は制御しません。したがって上記の「トークンデータベースの読者はログイン済みユーザーの GitHub セッションを乗っ取れる」というリスクは、`github_refresh_enabled` の設定に関わらず builtin mode にも同様に適用されます。

## TLS 終端（ローカル HTTPS）

mcp-gateway 自体で TLS を終端する場合、PEM 形式の証明書と秘密鍵のパスをペアで指定します:

```bash
MCP_GATEWAY_TLS_CERT_PATH=/data/certs/localhost.pem
MCP_GATEWAY_TLS_KEY_PATH=/data/certs/localhost-key.pem
MCP_GATEWAY_PUBLIC_URL=https://localhost:8080
```

- 両方が設定されている場合のみ HTTPS で listen します。片方のみの設定、またはファイルが存在しない場合は起動時にエラー終了します（フェイルファスト）。
- 自己署名証明書の自動生成は行いません。ローカル開発では [mkcert](https://github.com/FiloSottile/mkcert) 等で信頼済み証明書を生成してください（Docker 運用でのセットアップ自動化は Mcp-Docker 側で提供）。
- `MCP_GATEWAY_PUBLIC_URL` 未設定時のデフォルトスキームは、TLS 有効時は自動的に `https` になります。
- TLS リスナーは**デフォルトで HTTP/2 を有効化**します。長寿命 SSE GET と後続 POST を同じ h2 セッションで多重化できなかった undici の問題（[#204](https://github.com/scottlz0310/mcp-gateway/issues/204)）は undici 8.8.0 で修正され、Node.js 26.5.1 は修正版の undici 8.9.0 を同梱しています。Node.js 26.5.1 上の mcp-resource-subscriber で、SSE GET を保持したまま同一 h2 セッションの POST が応答し、502 が発生しないことを確認済みです（[#206](https://github.com/scottlz0310/mcp-gateway/issues/206)）。修正前の undici を使用するクライアントが残る環境では、`MCP_GATEWAY_ENABLE_HTTP2=false` で HTTP/1.1 のみに固定できます。

## リバースプロキシヘッダー

リバースプロキシで mcp-gateway の前段で TLS を終端する場合:

```bash
MCP_GATEWAY_PUBLIC_URL=https://mcp.example.com
MCP_GATEWAY_BIND_ADDR=127.0.0.1:8080
MCP_GATEWAY_TRUSTED_PROXIES=127.0.0.1/32,10.0.0.0/8
```

直前のピア IP が `trusted_proxies` に含まれるリクエストのみ以下に影響できます:

| ヘッダー | 効果 |
|---------|------|
| `X-Forwarded-Proto` | 値が `http` または `https` の場合にリクエストスキームを設定。 |
| `X-Forwarded-Host` | 基本的なホスト検証後に `r.Host` を設定。 |
| `X-Forwarded-For` | 信頼済みプロキシが提供する最右端の有効 IP を `r.RemoteAddr` に設定。 |

信頼されていない転送ヘッダーは、認証・セットアップチェック・アクセスログ・プロキシ処理の前にすべて除去されます。

## OAuth および MCP エンドポイント

| パス | メソッド | 説明 |
|------|---------|------|
| `/.well-known/oauth-authorization-server` | GET | RFC 8414 authorization server メタデータ。 |
| `/.well-known/openid-configuration` | GET | OIDC Discovery ドキュメント（gateway が OIDC Provider として動作する場合）。 |
| `/.well-known/oauth-protected-resource` | GET | ゲートウェイ全体の RFC 9728 Protected Resource Metadata。ルートプレフィックスルートもカバー。 |
| `/.well-known/oauth-protected-resource/<prefix>` | GET | 認証済み非ルートルートのルート単位 Protected Resource Metadata。例: `/.well-known/oauth-protected-resource/mcp/github`。 |
| `/authorize` | GET | OAuth 2.0 authorization エンドポイント。 |
| `/callback` | GET | GitHub OAuth コールバック。 |
| `/device_authorization` | POST | Device Authorization Grant エンドポイント（RFC 8628）。 |
| `/token` | POST | authorization code + PKCE・device code・refresh token grant 用トークンエンドポイント。 |
| `/revoke` | POST | RFC 7009 トークン失効エンドポイント。`token` + 任意 `token_type_hint`（`access_token`/`refresh_token`）を受け付ける。refresh token の失効はファミリー全体（RFC 6819 reuse detection と同じ仕組み）と、builtin mode ではそのファミリーに紐づく現行アクセストークン（gateway JWT）の即時失効も行う。未知・期限切れ・二重失効のトークンでも常に 200 を返す（RFC 7009 §2.2）。 |
| `/register` | POST | RFC 7591 形式の動的クライアント登録。 |
| `/jwks` | GET | JSON Web Key Set（gateway が OIDC Provider として動作する場合）。 |
| `/userinfo` | GET | OIDC UserInfo エンドポイント。 |
| `/upstream/callback/{routeName}` | GET | upstream OAuth の authorization code コールバック。`authorization_code` フロー有効ルートに自動登録。`client_credentials` フローでは未使用。 |
| `/setup` | GET/POST | 初回起動セットアップウィザードエンドポイント（セットアップモード時のみ利用可能）。 |
| `/health` | GET | 通常モードのヘルスチェック。 |
| `/<prefix>` | ANY | マッチした upstream へのリバースプロキシ。`auth=none` が設定されていない限り Bearer 検証が行われます。 |

## OAuth 監査ログ

認証開始、callback、token exchange、identity resolution、refresh、provider token rotation の成功・失敗を、標準出力と専用 JSON Lines ファイルの両方へ記録します。ファイルは 1 行 1 イベントで、`jq`、PowerShell、AI エージェントからそのまま解析できます。

### 既定パス

| 実行環境 | 既定パス |
|----------|---------|
| Windows | `%LOCALAPPDATA%\mcp-gateway\logs\auth-audit.jsonl` |
| Linux | `$XDG_STATE_HOME/mcp-gateway/logs/auth-audit.jsonl`。`XDG_STATE_HOME` 未設定時は `$HOME/.local/state/mcp-gateway/logs/auth-audit.jsonl` |
| macOS | `$HOME/Library/Logs/mcp-gateway/auth-audit.jsonl` |
| 公式コンテナイメージ | `/data/mcp-gateway/logs/auth-audit.jsonl` |

公式イメージは Linux 標準の `XDG_STATE_HOME=/data` を設定済みです。compose を使わない `docker run` でも起動でき、`/data` に volume をマウントするとコンテナ再作成後も保持できます。

```bash
docker run --rm -p 8080:8080 \
  --volume mcp-gateway-data:/data \
  --env OAUTH_CLIENT_ID=<client-id> \
  --env OAUTH_CLIENT_SECRET=<client-secret> \
  --env MCP_GATEWAY_BIND_ADDR=0.0.0.0:8080 \
  --env 'ROUTE_EXAMPLE=/mcp/example|http://example-mcp:8081' \
  ghcr.io/scottlz0310/mcp-gateway:latest
```

ネイティブ実行ではリポジトリを汚さないよう、相対パス・カレントワーキングディレクトリへのフォールバック・Git worktree 配下の明示パスを拒否します。OS のユーザー領域を解決できない場合や、保存先を作成・追記できない場合は起動失敗となります。

### ローテーション

- 現行ファイルが `MCP_GATEWAY_AUTH_AUDIT_MAX_SIZE_MB` に達すると UTC タイムスタンプ付きファイルへローテーションします。
- `MCP_GATEWAY_AUTH_AUDIT_MAX_BACKUPS` を超えた世代と、`MCP_GATEWAY_AUTH_AUDIT_MAX_AGE_DAYS` を超えたファイルを削除します。
- ローテーション済みファイルは AI 解析時に直接読めるよう圧縮しません。
- ファイルはオーナーのみ読み書き可能な permission で作成します。

監査イベントには token、authorization code、device code、OAuth `state`、client secret、Authorization ヘッダー、provider レスポンスボディを保存しません。相関が必要なトークンは短い SHA-256 フィンガープリントのみを記録します。

## GitHub OAuth リフレッシュトークンローテーション

GitHub App で **Expire user authorization tokens** が有効な場合、GitHub は各アクセストークンとともに `refresh_token` と `expires_in` を返します（通常アクセストークン有効期間 8 時間、リフレッシュトークン有効期間 6 ヶ月）。ゲートウェイはこれらのトークンを有効期限前に透過的にローテーションできるため、長時間実行の upstream 操作中にアクセストークンが無効になりません。

GitHub Apps は `ghu_` プレフィックス（user-to-server アクセストークン）と `ghr_` プレフィックス（リフレッシュトークン）のトークンを発行します。ゲートウェイは両プレフィックスを従来の `gho_` OAuth App トークンと同様に処理します。追加設定は不要です。

### GitHub App でのトークン有効期限設定

GitHub App にトークン有効期限を設定するには:

1. **GitHub -> Settings -> Developer settings -> GitHub Apps -> Your App -> General** を開く。
2. **"User authorization tokens"** までスクロールし、**"Expire user authorization tokens"** にチェックを入れる。
3. 変更を保存する。

この設定後、すべての OAuth 交換で `expires_in`（8 時間）と `refresh_token`（`ghr_…`、約 6 ヶ月有効）が `ghu_` アクセストークンとともに返されます。

### ゲートウェイでのローテーション有効化

以下のいずれかを設定します:

```bash
MCP_GATEWAY_GITHUB_REFRESH_ENABLED=true
```

または `config.yaml` で:

```yaml
gateway:
  github_refresh_enabled: true
```

デフォルトは `false` です。GitHub App のトークン有効期限が無効でも安全に有効化できます（キャッシュされたトークンエントリに `expires_in` ヒントとリフレッシュトークンがある場合のみローテーションパスが起動します。非期限切れ設定ではこれらは提供されません）。

### 動作

フラグが有効な場合、すべての `ValidateToken` 呼び出しがベアラートークンのキャッシュされたプロバイダーメタデータを検査します:

1. プロバイダーアクセス有効期限まで約 5 分以上ある場合はローテーションをスキップし、通常通りキャッシュされた subject を返す。
2. アクセス有効期限がリードウィンドウ内の場合、ゲートウェイは `grant_type=refresh_token` で GitHub トークンエンドポイントを呼び出す。
3. 成功した場合、新しいアクセストークンは独自のキーでキャッシュされ、ローテーション済みトークンがリクエストコンテキスト経由で upstream MCP サーバーに転送される。元のトークンのキャッシュエントリは**保持**され（MCP クライアントは引き続き元のベアラーを提示）、プロバイダーリフレッシュメタデータが新たに発行されたリフレッシュトークン/有効期限に更新されます。
4. プロバイダー失敗時はゲートウェイが `rotation_failed` をログに記録し、キャッシュをそのままにして元のトークンで処理を続行。upstream がその後 401 を返した場合は既存のキャッシュ無効化パスが再認証を処理。

ローテーションはそれをトリガーしたリクエストに束縛されます。古いトークンでの進行中の upstream 操作は中断されません。`review-raven` の watch goroutine（issue #70）は watch 開始時にキャプチャしたトークンのみを参照します。Phase A は後続リクエストがローテーション済みトークンを使用するようにしますが、バックグラウンドワーカーに遡及的にパッチを当てません。

**builtin mode（`OAUTH_PROVIDER=builtin`）でのローテーション:** クライアントに渡すアクセストークンはゲートウェイ署名の JWT であり、GitHub アクセストークン自体ではないため、上記の動作（`ValidateToken` がキャッシュヒット時にローテーションする）はそのままでは builtin mode に適用できません。代わりに、`EnsureFreshAccessTokenForSubject`（Phase B delegated access、`upstream_provider_token=true` ルートおよび `/internal/v1/whoami` が使用）を呼び出した際にのみローテーションを試行します。ローテーション成功時はキャッシュキー（JWT）自体は変更されず、紐づく GitHub アクセストークン/リフレッシュトークン/有効期限のみが同じ JWT の記録内で更新されます。`ValidateToken`（JWT の検証のみ）はローテーションを一切試行しません — JWT 検証と provider トークンのローテーションは独立した関心事であり、ローテーションが必要になるのは delegated access が GitHub アクセストークンを実際に使う場面のみのためです。ローテーション失敗時の扱いは非 builtin mode と同様です（一時的失敗はメタデータを保持して次回リトライ、永続的失敗はメタデータをクリアして以後 `ErrSubjectNotFound` を返す）。

### 制限事項

- `MCP_GATEWAY_TOKEN_STORE_PATH` が未設定の場合、ゲートウェイ再起動時にリフレッシュトークンが失われます。再起動をまたいでローテーションを継続するにはトークン状態をディスクに永続化してください。
- builtin mode（`OAUTH_PROVIDER=builtin`）の delegated access（`EnsureFreshAccessTokenForSubject`、`upstream_provider_token=true` ルート、`/internal/v1/whoami`）には永続トークンストアが実質必須です。`MCP_GATEWAY_TOKEN_STORE_PATH` を空値に設定した in-memory 構成では、JWT に紐付けた GitHub アクセストークンがトークンキャッシュ TTL（`TOKEN_CACHE_TTL_MIN`、既定 30 分）の経過またはゲートウェイ再起動で失われます。JWT 自体は有効期限（90 日）まで検証に成功し続けるため、プロキシ転送は正常に動作したまま delegated access だけが再認証を要求し続ける、原因に気づきにくい状態になります。
- ローテーションリードタイムは約 5 分に固定されています。上流操作が著しく長いオペレーターは、リードタイムを拡大するより Phase B（委任バックグラウンドアクセス）を検討してください。
- ローテーションには `gateway.github_client_secret` が必要です。GitHub のリフレッシュエンドポイントが初回交換と同様にローテーションリクエストを認証するためです。

### トラブルシューティング

| 症状 | 原因の可能性 |
|------|------------|
| ログに `rotation_failed err=bad_refresh_token` | GitHub App がリフレッシュトークンを失効させた（手動またはユーザーがリセットしたため）。クライアントは再認証が必要。 |
| すべてのトークンでローテーションが発生しない | GitHub App の "Expire user authorization tokens" が有効でないか、トークンレスポンスに `expires_in` がない。GitHub Developer Settings でアプリ設定を確認してください。 |
| ローテーションは発生するが upstream が引き続き 401 を返す | upstream が独自の状態で古いベアラーをキャッシュしている（例: `review-raven` の watch goroutine）。Phase A は意図的に upstream 状態をパッチしません — これは Phase B のスコープです。 |

## OAuth リソースパラメーター

ゲートウェイは RFC 8707 `resource` パラメーターを以下でサポートします:

- `/authorize`
- `/device_authorization`
- `grant_type=refresh_token` を使用した `/token`

resource は登録済みのゲートウェイまたはルート audience と一致する必要があります。移行猶予期間中は `MCP_GATEWAY_TOKEN_AUDIENCE_STRICT=false` の間、audience メタデータが記録されていない旧トークンが受け入れられます。
