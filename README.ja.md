# mcp-gateway

MCP サービス群への統合ゲートウェイ（GitHub OAuth 認証・リクエストルーティング・Fly.io デプロイ対応）

> **[mcp-docker](https://github.com/scottlz0310/Mcp-Docker) エコシステムの一部** — `mcp-docker` および `copilot-review-mcp` と組み合わせて、コンポーザブルなセルフホスト MCP インフラスタックを構成します。

## 概要

`mcp-gateway` は複数の MCP サービスへのリクエストルーティングと GitHub OAuth 2.0 認証を一元管理するリバースプロキシです。MCP クライアント（Claude Desktop、VS Code GitHub Copilot など）の単一エントリポイントとして機能し、PKCE 付き OAuth 2.0 認可コードフローを処理してから認証済みリクエストを上流 MCP サーバーへ転送します。

`github-oauth-proxy` の後継として設計されています（[Mcp-Docker#102](https://github.com/scottlz0310/Mcp-Docker/issues/102)）。

## アーキテクチャ

```
MCP クライアント（Claude Desktop / VS Code / etc.）
      │
      ▼
mcp-gateway (:8080)
  ├── OAuth ファサード   /authorize  /callback  /token  /register
  ├── Bearer 検証       (GitHub API キャッシュ付き)
  └── ルーティング（最長プレフィックスマッチ）
        ├── /mcp/github           → github-mcp-server  :8082
        └── /mcp/copilot-review   → copilot-review-mcp :8083
```

### 3リポジトリ構成

| リポジトリ | 役割 |
|-----------|------|
| **mcp-gateway**（本リポジトリ） | OAuth 2.0 認証 + ルーティングゲートウェイ |
| [mcp-docker](https://github.com/scottlz0310/Mcp-Docker) | MCP スタック全体の Docker Compose オーケストレーション |
| [copilot-review-mcp](https://github.com/scottlz0310/copilot-review-mcp) | Copilot コードレビュー MCP サーバー |

## 初回起動セットアップウィザード

起動時に必須の値（`GITHUB_MCP_CLIENT_ID`・`GITHUB_MCP_CLIENT_SECRET`・最低1件のルート）のいずれかが不足している場合、ゲートウェイは終了せず自動的に**セットアップモード**に移行します。

### 動作の流れ

1. ゲートウェイは通常ポート（デフォルト `:8080`）でセットアップモードとして起動します。
2. ワンタイムセットアップトークン（TTL 15 分）が標準出力に出力されます:
   ```
   {"level":"warn","msg":"mcp-gateway starting in setup mode — configure via /setup",
    "setup_url":"http://127.0.0.1:8080/setup?token=<TOKEN>",
    "token":"<TOKEN>"}
   ```
3. `/setup` 以外のすべてのルートは `503 {"error":"setup_required","setup_url":"..."}` を返します。

### curl でのセットアップ完了

```bash
# 1. 不足している設定項目を確認
curl "http://127.0.0.1:8080/setup?token=<TOKEN>"
# → {"missing":["client_id","client_secret","routes"],"hint":"POST /setup ..."}

# 2. 設定を送信
curl -X POST "http://127.0.0.1:8080/setup?token=<TOKEN>" \
  -H "Content-Type: application/json" \
  -d '{
    "client_id": "Ov23liXXXXXXXXXX",
    "client_secret": "your-github-oauth-secret",
    "routes": [
      {"name": "github", "prefix": "/mcp/github", "upstream": "http://github-mcp:8082"},
      {"name": "playwright", "prefix": "/mcp/playwright", "upstream": "http://playwright:8931", "no_auth": true}
    ]
  }'
# → {"saved":true,"restart_required":true}
```

4. ゲートウェイは提供されたフィールドを `config.yaml` に保存し（`client_secret` が POST ボディに含まれる場合は `age` で暗号化）、終了コード `0` で終了します。
5. プロセススーパーバイザー（例: `restart: unless-stopped` の Docker Compose、systemd など）がゲートウェイを**通常モード**で再起動します。

### API リファレンス

| メソッド | パス | 説明 |
|---------|------|------|
| `GET` | `/setup?token=<TOKEN>` | 不足している設定項目のリストを `{"missing":[...]}` として返す |
| `POST` | `/setup?token=<TOKEN>` | JSON ボディを受け取り、config を保存して `os.Exit(0)` を呼び出す |

**POST ボディスキーマ:**

```json
{
  "client_id": "string (GET /setup で missing に含まれる場合のみ必須)",
  "client_secret": "string (GET /setup で missing に含まれる場合のみ必須)",
  "routes": [
    {
      "name": "string (必須)",
      "prefix": "/スラッシュ始まり (必須)",
      "upstream": "http(s)://host:port (必須)",
      "no_auth": false
    }
  ]
}
```

**エラーコード:** `401` トークン無効 · `408` トークン期限切れ · `409` 設定済み · `422` バリデーションエラー

> **セキュリティ上の注意:** セットアップトークンは成功した `POST /setup` 完了後に無効化され、15 分で期限切れになります。`GET` リクエストや失敗した `POST` は有効期限内であれば再試行可能です。本番環境（HTTPS）では POST リクエストは TLS 経由で行ってください。平文 HTTP で POST を受信した場合、ゲートウェイは警告をログに出力します。

## 設定

### GitHub OAuth 認証情報

起動時、ゲートウェイは GitHub OAuth 認証情報を以下の優先順位で解決します:

| 認証情報 | 優先ソース | フォールバック |
|---------|------------|--------------|
| `GITHUB_MCP_CLIENT_ID` | `GITHUB_MCP_CLIENT_ID` 環境変数 | `config.yaml` の `auth.github_client_id` |
| `GITHUB_MCP_CLIENT_SECRET` | `config.yaml` の `auth.github_client_secret`（`ENC[age:]...` 形式も可） | `GITHUB_MCP_CLIENT_SECRET` 環境変数 *(初回起動時のシードのみ — config.yaml に値が存在する場合は無視)* |

また、`ROUTE_<NAME>` によるルート設定が最低1つ必要です（未設定の場合は起動時にエラー終了）。

### シークレット暗号化

ゲートウェイは GitHub OAuth クライアントシークレットを [age](https://age-encryption.org/) X25519 暗号化を用いて `config.yaml` に**暗号化して保存**できます。

#### 動作の仕組み

起動時に以下を実行します:

1. `gateway.key`（パス: `MCP_GATEWAY_KEY_PATH`、デフォルト `./gateway.key`）から X25519 キーをロード（または生成）
2. `config.yaml`（`MCP_CONFIG_FILE`、デフォルト `./config.yaml`）が存在すれば読み込む
3. 以下の優先順位で `github_client_secret` を解決:
   - `config.yaml` に `ENC[age:]...` が存在 → 復号して使用
   - `config.yaml` に平文が存在 → 暗号化してファイルを書き換え、平文を使用
   - config に値なし + `GITHUB_MCP_CLIENT_SECRET` 環境変数あり → 暗号化して config に保存し使用
   - いずれもなし → 明確なエラーメッセージで起動失敗

シークレットは**絶対にログに出力されません**（平文・`ENC[...]` 暗号文・キー内容のいずれも）。

#### キーファイル (`gateway.key`)

キーファイルには `age-keygen` 互換の X25519 identity 文字列（`AGE-SECRET-KEY-1...`）が保存されます。

**生成優先順位:**

| 条件 | 結果 |
|------|------|
| `gateway.key` が存在する | そのままロード; `MCP_GATEWAY_MASTER_KEY` は**無視** |
| `gateway.key` なし + `MCP_GATEWAY_MASTER_KEY` 設定済み | HKDF-SHA256 で X25519 キーを決定論的に導出; ファイルに保存 |
| `gateway.key` なし + マスターキーなし | ランダムな X25519 キーを生成; ファイルに保存 |

> **⚠ 破損は致命的エラー。** `gateway.key` が存在するが空・読み取り不能・形式不正の場合、ゲートウェイは再生成**しません** — 即座に終了します。これは意図しない上書きによる暗号化シークレットの永久消失を防ぐためです。復旧するには `gateway.key` をバックアップから復元するか、既知のキーで `config.yaml` を再暗号化してください。

ファイルは `0600` パーミッションで書き込まれます。`chmod` が期待通り動作しない Windows ボリュームでは警告をログ出力します。

**`gateway.key` を安全にバックアップしてください。** キーファイルを紛失し `MCP_GATEWAY_MASTER_KEY` を使用していなかった場合（ランダム生成時）、`config.yaml` の暗号化シークレットは復元不能になります。

#### `MCP_GATEWAY_MASTER_KEY`

設定されている場合、マスターキーを用いて X25519 キーを決定論的に導出（HKDF-SHA256）します。これにより、別途キーファイルのバックアップなしでシークレット暗号化が可能になります — 同じマスターキーは常に同じ `gateway.key` を生成します。

**要件:**
- 最低 **32 バイト** — 短い値は起動時に拒否されます
- 十分にランダムな値を使用してください（例: `openssl rand -hex 32` の出力）
- **マスターキーの漏えい = 導出キーの漏えい = 暗号化シークレットが復号可能** — シークレットとして厳重に管理してください

> `gateway.key` が存在する場合、`MCP_GATEWAY_MASTER_KEY` は無視されます。キーファイルの初回生成時のみ使用されます。

`MCP_MASTER_KEY` は `MCP_GATEWAY_MASTER_KEY` の後方互換エイリアスとして受け付けます。

#### `config.yaml` の例

```yaml
auth:
  github_client_id: "Ov23liXXXX"
  github_client_secret: "ENC[age:]<base64-ciphertext>"
gateway:
  public_url: "http://127.0.0.1:8080"
  port: "8080"
  oauth_scopes: "repo,user"
  trusted_proxies:
    - "127.0.0.1/32"
```

`gateway:` 配下はすべてオプションで、対応する環境変数またはデフォルト値にフォールバックします。

#### Docker Compose の設定例

```yaml
services:
  mcp-gateway:
    volumes:
      - ./data:/data
    environment:
      MCP_GATEWAY_KEY_PATH: /data/gateway.key
      MCP_CONFIG_FILE: /data/config.yaml
      # 初回のみ — gateway.key が存在すれば省略可:
      # MCP_GATEWAY_MASTER_KEY: "${MCP_GATEWAY_MASTER_KEY}"
      GITHUB_MCP_CLIENT_ID: "${GITHUB_MCP_CLIENT_ID}"
      # GITHUB_MCP_CLIENT_SECRET は初回起動時に config.yaml へシードする場合のみ必要:
      # GITHUB_MCP_CLIENT_SECRET: "${GITHUB_MCP_CLIENT_SECRET}"
      ROUTE_GITHUB: /mcp/github|http://github-mcp:8082
```

### 必須環境変数

| 変数 | 説明 |
|------|------|
| `GITHUB_MCP_CLIENT_ID` | GitHub OAuth App の Client ID |
| `ROUTE_<NAME>` | ルーティング設定（最低1件必要、下記参照） |

> `GITHUB_MCP_CLIENT_SECRET` は、`config.yaml` に暗号化済みシークレット (`ENC[age:]...`) が存在する場合は不要です。
> 存在しない場合は、初回起動時のシードとしてこの環境変数が必要です（詳細は「シークレット暗号化」を参照）。

### ルーティング設定

`ROUTE_<NAME>=<prefix>|<upstream_url>` の形式で設定します。

```bash
ROUTE_GITHUB=/mcp/github|http://github-mcp:8082
ROUTE_COPILOT_REVIEW=/mcp/copilot-review|http://copilot-review-mcp:8083
```

複数のルートを設定した場合、**最長プレフィックスが優先**されます。

特定のルートで Bearer 検証を無効にするには、第3セグメントとして `|auth=none` を追加します（公開エンドポイントや認証前のパスに使用）:

```bash
ROUTE_PUBLIC=/public|http://public-svc:8083|auth=none
```

### オプション環境変数

| 変数 | デフォルト | 説明 |
|------|-----------|------|
| `MCP_GATEWAY_KEY_PATH` | `./gateway.key` | X25519 暗号化キーファイルのパス（[シークレット暗号化](#シークレット暗号化) 参照） |
| `MCP_CONFIG_FILE` | `./config.yaml` | 永続設定を格納する `config.yaml` のパス |
| `MCP_GATEWAY_MASTER_KEY` | — | 決定論的キー導出に使用するマスターキー（≥32 バイト; [シークレット暗号化](#シークレット暗号化) 参照） |
| `MCP_GATEWAY_PUBLIC_URL` | `http://127.0.0.1:8080` | OAuth コールバック・discovery メタデータ・PRM に使用する外部公開 URL（`MCP_GATEWAY_BASE_URL` の後継） |
| `MCP_GATEWAY_BIND_ADDR` | `127.0.0.1:8080` | HTTP リスナーのバインドアドレス。Docker デプロイでは `0.0.0.0:<port>` に変更する。同一ホスト上のリバースプロキシ経由の場合はデフォルト `127.0.0.1:<port>` のままで良い |
| `MCP_GATEWAY_TRUSTED_PROXIES` | — | `X-Forwarded-*` を信頼するリバースプロキシの CIDR リスト（カンマ区切り。例: `127.0.0.1/32,10.0.0.0/8`） |
| `MCP_GATEWAY_BASE_URL` | — | **非推奨** — `MCP_GATEWAY_PUBLIC_URL` のエイリアス。将来のリリースで削除予定 |
| `MCP_GATEWAY_PORT` | `8080` | `bind_addr` と `public_url` のデフォルト値を導出する際のポート番号。実際の待受アドレスは `MCP_GATEWAY_BIND_ADDR` で制御する |
| `MCP_GATEWAY_TOKEN_STORE_PATH` | `/data/tokens.json` | 永続トークンストアのファイルパス（[認証状態の永続化](#認証状態の永続化) 参照） |
| `GITHUB_MCP_OAUTH_SCOPES` | `repo,user` | GitHub OAuth スコープ |
| `LOG_LEVEL` | `info` | ログレベル (`debug`/`info`/`warn`/`error`) |
| `SESSION_TTL_MIN` | `10` | OAuth セッション有効期間（分） |
| `TOKEN_CACHE_TTL_MIN` | `30` | トークン検証キャッシュ TTL（分）— `MCP_GATEWAY_TOKEN_STORE_PATH` を空文字に明示設定した場合のみ使用 |
| `TOKEN_EXPIRES_IN_SEC` | `7776000` | クライアントへ通知するトークン有効期限（秒、デフォルト 90 日）。永続ストアのエントリ TTL にも使用 |
| `GITHUB_MCP_UPSTREAM_URL` | — | **非推奨**: 単一アップストリーム（`ROUTE_*` 未設定時のフォールバック） |

### リバースプロキシヘッダ

nginx / Caddy / fly.io edge proxy などで TLS を gateway の手前で終端する場合は、
`MCP_GATEWAY_PUBLIC_URL` / `gateway.public_url` をクライアントから見える外部 URL に設定し、
信頼するプロキシの CIDR を指定します。

```bash
MCP_GATEWAY_PUBLIC_URL=https://mcp.example.com
MCP_GATEWAY_BIND_ADDR=127.0.0.1:8080
MCP_GATEWAY_TRUSTED_PROXIES=127.0.0.1/32,10.0.0.0/8
```

信頼済みプロキシからのリクエストだけが `X-Forwarded-Proto` / `X-Forwarded-Host` /
`X-Forwarded-For` を後段の request に反映できます。未信頼の送信元から届いた forwarded
headers は削除されます。不正な CIDR は起動時エラーになります。

信頼済みプロキシは、クライアント由来の `X-Forwarded-For` をそのまま渡さず、上書きまたは
サニタイズしてください。gateway は XFF を右側から読みますが、このヘッダの所有者は
プロキシに限定する前提です。

### 認証状態の永続化

> **Docker デフォルト:** デフォルトのストアパス `/data/tokens.json` は Docker 運用向けです。Docker イメージは `/data` を適切なパーミッションで事前作成しています。Docker 以外（`go run` やバイナリ直接実行）では `/data` が存在しないため起動に失敗します。その場合は `MCP_GATEWAY_TOKEN_STORE_PATH` を書き込み可能なパス（例: `./tokens.json`）に設定するか、永続化を無効にするため空文字を設定してください。

デフォルトでは、検証済みトークンの状態は `/data/tokens.json` に永続化されます。通常運用では **gateway を再起動しても MCP クライアント（VS Code、Claude Desktop など）の再認証は不要です**。

ストアパスを変更したい場合は `MCP_GATEWAY_TOKEN_STORE_PATH` を設定します。永続化を無効にしてインメモリのみに戻す場合（本番環境では非推奨）は空文字を設定します：

```bash
MCP_GATEWAY_TOKEN_STORE_PATH=/data/tokens.json  # デフォルト（Docker）
MCP_GATEWAY_TOKEN_STORE_PATH=./tokens.json       # ローカル実行時
MCP_GATEWAY_TOKEN_STORE_PATH=                   # 永続化を無効化（非推奨）
```

設定すると gateway は以下を行います：

- 起動時にファイルから検証済みトークン ↔ ユーザー識別子のマッピングを読み込む
- 認証成功のたびにファイルへ保存（期限は `TOKEN_EXPIRES_IN_SEC`、デフォルト 90 日）
- 毎分、期限切れエントリを自動削除
- ファイルパーミッション `0600`（所有者のみ読み書き）で書き込む
- SHA-256 ハッシュ済みのキーのみ保存（生のトークン値はディスクに書き込まれない）

`MCP_GATEWAY_TOKEN_STORE_PATH` を設定すると、**リフレッシュトークン永続化**が有効になります。初回のリフレッシュトークン発行時（`authorization_code` や device grant の成功時を含み、`refresh_token` グラントを待たずに発生し得ます）に `<path>.refresh`（例: `/data/tokens.json.refresh`）というファイルが書き込まれます（起動直後は存在しない場合があります）。これにより gateway が再起動しても発行済みリフレッシュトークンが引き継がれ、クライアントは `refresh_token` グラントで透過的にセッションを継続できます（ブラウザ再認証不要）。

> **セキュリティ上の注意:** `.refresh` ファイルには、ハッシュ済みのリフレッシュトークンキーに加え、**関連する access token 値が平文で保存されます**。gateway はリフレッシュ時に上流プロバイダーへ access token を再提示する必要があるため、平文保存は不可避です。ファイルはパーミッション `0600`（所有者のみ読み書き）で書き込まれます。プライマリトークンストアファイルと同等の機密性として扱い、高セキュリティ環境では暗号化ボリュームや `tmpfs` マウント上に配置することを推奨します。

> **Docker ユーザー:** ストアパスに named volume をマウントしてコンテナ入れ替え後もデータを保持してください。
> 推奨の `docker-compose.yml` スニペットは [mcp-docker](https://github.com/scottlz0310/Mcp-Docker) の関連 Issue を参照してください。

全クライアントの認証状態をリセット（再認証を強制）したい場合は、ストアファイルを削除して gateway を再起動してください。

## エンドポイント

| パス | メソッド | 説明 |
|------|---------|------|
| `/.well-known/oauth-authorization-server` | GET | RFC 8414 メタデータ |
| `/authorize` | GET | OAuth 認可エンドポイント |
| `/callback` | GET | GitHub OAuth コールバック |
| `/device_authorization` | POST | Device Authorization Grant エンドポイント（RFC 8628） |
| `/token` | POST | トークンエンドポイント（`authorization_code` + PKCE、`urn:ietf:params:oauth:grant-type:device_code`、`refresh_token` グラント対応） |
| `/register` | POST | RFC 7591 動的クライアント登録（疑似） |
| `/health` | GET | ヘルスチェック |
| `/<prefix>` | ANY | マッチしたルート設定に応じて認証（例: Bearer 検証または `auth=none`）を適用し、対応アップストリームへリバースプロキシ |

## クイックスタート

### 1. GitHub OAuth App の作成

**GitHub → Settings → Developer settings → OAuth Apps → New OAuth App** から:

- **Authorization callback URL**: `http://127.0.0.1:8080/callback` (または `MCP_GATEWAY_PUBLIC_URL` + `/callback`)

### 2. Docker Compose で起動

```yaml
services:
  mcp-gateway:
    image: ghcr.io/scottlz0310/mcp-gateway:latest
    ports:
      - "8080:8080"
    environment:
      GITHUB_MCP_CLIENT_ID: <your-client-id>
      GITHUB_MCP_CLIENT_SECRET: <your-client-secret>
      MCP_GATEWAY_BIND_ADDR: 0.0.0.0:8080
      MCP_GATEWAY_PUBLIC_URL: http://127.0.0.1:8080
      ROUTE_GITHUB: /mcp/github|http://github-mcp:8082
    depends_on:
      - github-mcp
```

### 2a. マルチアップストリーム: github-mcp + copilot-review-mcp

`ROUTE_*` を複数設定することで、単一ゲートウェイから複数の MCP サービスをルーティングできます。
`copilot-review-mcp` を含む完全な例は [`examples/copilot-review-routing/`](examples/copilot-review-routing/) を参照してください。

```yaml
services:
  mcp-gateway:
    image: ghcr.io/scottlz0310/mcp-gateway:latest
    ports:
      - "8080:8080"
    environment:
      GITHUB_MCP_CLIENT_ID: <your-client-id>
      GITHUB_MCP_CLIENT_SECRET: <your-client-secret>
      MCP_GATEWAY_BIND_ADDR: 0.0.0.0:8080
      MCP_GATEWAY_PUBLIC_URL: http://127.0.0.1:8080
      ROUTE_GITHUB: /mcp/github|http://github-mcp:8082
      ROUTE_COPILOT_REVIEW: /mcp/copilot-review|http://copilot-review-mcp:8083
    depends_on:
      - github-mcp
      - copilot-review-mcp
```

> **動作原理**: `copilot-review-mcp` は Go の `ServeMux` サブツリーハンドラ (`/mcp/`) を使用しているため、
> mcp-gateway が転送する `/mcp/copilot-review` パスは **`copilot-review-mcp` のコード変更なし** で正しくハンドルされます。

### 3. MCP クライアントの設定

MCP クライアント設定ファイル（例: `claude_desktop_config.json`）に追加してください:

```json
{
  "mcpServers": {
    "github": {
      "url": "http://127.0.0.1:8080/mcp/github",
      "transport": "http"
    },
    "copilot-review": {
      "url": "http://127.0.0.1:8080/mcp/copilot-review",
      "transport": "http"
    }
  }
}
```

## 開発

```bash
# テスト
go test ./...

# ビルド
go build ./cmd/server

# Docker ビルド
docker build -t mcp-gateway .
```

## 内部設計

### Provider インターフェース

OAuth プロバイダーは `Provider` インターフェースで抽象化されており、auth ハンドラやミドルウェアを変更することなく新しい ID プロバイダー（fly.io、OIDC など）を追加しやすい構造になっています:

```go
type Provider interface {
    Name() string
    ClientID() string
    Scopes() string
    AuthorizeURL(state, codeChallenge string) string
    ExchangeCode(ctx context.Context, code string) (token string, scopes []string, err error)
    ValidateToken(ctx context.Context, token string) (Identity, error)
}

type Identity struct {
    Provider    string
    Subject     string // 上流に転送する安定したユーザー識別子
    DisplayName string // ログ用のオプショナルな表示名
}
```

プロキシは上流 MCP サーバーに以下のヘッダーを転送します:

| ヘッダー | 値 |
|---------|---|
| `X-Authenticated-User` | `Identity.Subject`（正規のプロバイダー非依存識別子） |
| `X-GitHub-Login` | `X-Authenticated-User` と同値（後方互換のため両方送出） |

なりすまし可能な受信ヘッダー（`X-Authenticated-User`、`X-GitHub-Login`）はプロキシ前にストリップされます。

## Docker イメージ

```
ghcr.io/scottlz0310/mcp-gateway:latest
```

`gcr.io/distroless/static-debian12:nonroot` をベースにビルド — シェルなし・パッケージマネージャなし・非 root（UID 65532）で動作します。

## ライセンス

[LICENSE](LICENSE) を参照してください。
