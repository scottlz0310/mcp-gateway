# mcp-gateway

MCP サービス群への統合ゲートウェイ（GitHub OAuth 認証・リクエストルーティング・Fly.io デプロイ対応）

## 概要

`mcp-gateway` は複数の MCP サービスへのリクエストルーティングと GitHub OAuth 2.0 認証を一元管理するリバースプロキシです。`github-oauth-proxy` の後継として設計されています（[Mcp-Docker#102](https://github.com/scottlz0310/Mcp-Docker/issues/102)）。

## アーキテクチャ

```
MCP クライアント
      │
      ▼
mcp-gateway (:8080)
  ├── OAuth フロー   (/authorize, /callback, /token, /register)
  ├── Bearer 検証   (GitHub API キャッシュ付き)
  └── ルーティング
        ├── /mcp/github       → github-mcp:8082
        └── /mcp/copilot-review → copilot-review-mcp:8083
```

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
  base_url: "http://localhost:8080"
  port: "8080"
  oauth_scopes: "repo,user"
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
| `MCP_GATEWAY_BASE_URL` | `http://localhost:8080` | OAuth コールバック等に使用するベース URL |
| `MCP_GATEWAY_PORT` | `8080` | リスンポート |
| `MCP_GATEWAY_TOKEN_STORE_PATH` | `/data/tokens.json` | 永続トークンストアのファイルパス（[認証状態の永続化](#認証状態の永続化) 参照） |
| `GITHUB_MCP_OAUTH_SCOPES` | `repo,user` | GitHub OAuth スコープ |
| `LOG_LEVEL` | `info` | ログレベル (`debug`/`info`/`warn`/`error`) |
| `SESSION_TTL_MIN` | `10` | OAuth セッション有効期間（分） |
| `TOKEN_CACHE_TTL_MIN` | `30` | トークン検証キャッシュ TTL（分）— `MCP_GATEWAY_TOKEN_STORE_PATH` を空文字に明示設定した場合のみ使用 |
| `TOKEN_EXPIRES_IN_SEC` | `7776000` | クライアントへ通知するトークン有効期限（秒、デフォルト 90 日）。永続ストアのエントリ TTL にも使用 |
| `GITHUB_MCP_UPSTREAM_URL` | — | **非推奨**: 単一アップストリーム（`ROUTE_*` 未設定時のフォールバック） |

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

- **Authorization callback URL**: `http://localhost:8080/callback` (または `MCP_GATEWAY_BASE_URL` + `/callback`)

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
      MCP_GATEWAY_BASE_URL: http://localhost:8080
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
      MCP_GATEWAY_BASE_URL: http://localhost:8080
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
      "url": "http://localhost:8080/mcp/github",
      "transport": "http"
    },
    "copilot-review": {
      "url": "http://localhost:8080/mcp/copilot-review",
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
