# 運用ガイド

このガイドは mcp-gateway の日常運用、ヘルスチェック、ログ確認、移行手順、および一般的なリカバリ手順を説明します。

設定の詳細リファレンスは [configuration.md](configuration.md) を参照してください。

## 起動と停止

### Docker Compose

通常のセルフホストスタックには Docker Compose を使用します。

```bash
docker compose up -d mcp-gateway
docker compose logs -f mcp-gateway
docker compose stop mcp-gateway
docker compose restart mcp-gateway
```

Docker ポートフォワーディングを使用するには、ゲートウェイがコンテナ内のすべてのインターフェースでリッスンする必要があります:

```yaml
services:
  mcp-gateway:
    image: ghcr.io/scottlz0310/mcp-gateway:latest
    ports:
      - "8080:8080"
    environment:
      OAUTH_CLIENT_ID: <your-client-id>
      OAUTH_CLIENT_SECRET: <your-client-secret>
      MCP_GATEWAY_BIND_ADDR: 0.0.0.0:8080
      MCP_GATEWAY_PUBLIC_URL: http://127.0.0.1:8080
      ROUTE_GITHUB: /mcp/github|http://github-mcp:8082
```

`MCP_GATEWAY_PUBLIC_URL` は OAuth クライアントとユーザーのブラウザが到達できる URL である必要があります。`MCP_GATEWAY_BIND_ADDR` が `0.0.0.0:8080` の場合でも、ローカル Docker デプロイでは `http://127.0.0.1:8080` になることが多いです。

### ベアバイナリまたは `go run`

Docker 外で実行する場合、ランタイムファイルはデフォルトで OS ユーザー状態ディレクトリに保存されます（[設定リファレンス](configuration.md#環境変数) を参照）。ディレクトリは初回起動時に自動作成されます。明示的なパスに変更する場合は起動前に設定します:

```bash
export MCP_GATEWAY_TOKEN_STORE_PATH=/your/path/tokens.json
export MCP_CONFIG_FILE=/your/path/config.yaml
export MCP_GATEWAY_KEY_PATH=/your/path/gateway.key
export OAUTH_CLIENT_ID=<your-client-id>
export OAUTH_CLIENT_SECRET=<your-client-secret>
export ROUTE_GITHUB=/mcp/github|http://127.0.0.1:8082

go run ./cmd/server
```

ローカルバイナリのビルドと実行:

```bash
go build -o mcp-gateway ./cmd/server
./mcp-gateway
```

起動したスーパーバイザーでプロセスを停止します（`Ctrl-C`、`docker compose stop`、`systemctl stop` など）。mcp-gateway は特別なシャットダウンエンドポイントを必要としません。

## ヘルスチェック

通常モードでのヘルスチェック:

```bash
curl -fsS http://127.0.0.1:8080/health
```

期待されるレスポンス:

```json
{"status":"ok"}
```

ゲートウェイがセットアップモードの場合、`/health` は `503 setup_required` を返します（必要な設定が保存されるまで `/setup` のみが利用可能なため）。セットアップモードを確認する場合は `curl -i http://127.0.0.1:8080/health` を使用してください。`curl -f` は期待される 503 で非ゼロ終了し、レスポンスボディが隠れる場合があります。

コンテナのヘルスチェックには、ホストから、または公開ポートに到達できる別のコンテナから同じエンドポイントを使用します:

```bash
curl -fsS http://mcp-gateway:8080/health
```

## ログの読み方

mcp-gateway は Go の `log/slog` を使用して JSON ログを stdout に出力します。`LOG_LEVEL` を `debug`、`info`、`warn`、`error` のいずれかに設定します。デフォルトは `info` です。

各ログエントリには標準 `slog` フィールドが含まれます:

| フィールド | 意味 |
|-----------|------|
| `time` | JSON ハンドラが出力するタイムスタンプ |
| `level` | `DEBUG`、`INFO`、`WARN`、または `ERROR` |
| `msg` | イベント名 |

### HTTP アクセスログ

すべての HTTP リクエストはハンドラ返却後に `"http request"` ログを1件出力します。

| フィールド | 意味 |
|-----------|------|
| `method` | リクエストメソッド |
| `path` | クエリ文字列なしのリクエストパス |
| `status` | 最終 HTTP ステータスコード |
| `latency_ms` | リクエスト処理時間（ミリ秒） |
| `remote_addr` | 信頼済みプロキシ処理後のクライアントアドレス |

5xx レスポンスは `ERROR` でログ出力され、他のステータス範囲は `INFO` でログ出力されます。

例:

```json
{"level":"INFO","msg":"http request","method":"GET","path":"/health","status":200,"latency_ms":0,"remote_addr":"127.0.0.1:53321"}
```

### 起動とルーティングログ

起動時は各ルートで `"registered route"` を出力し、サーバーがリッスン準備完了後に `"mcp-gateway starting"` を出力します。

| メッセージ | 重要フィールド |
|-----------|-------------|
| `registered route` | `name`、`prefix`、`upstream`、`auth_required` |
| `mcp-gateway starting` | `bind_addr`、`public_url`、`provider`、`routes`、`trusted_proxies`、`token_audience_strict` |
| `setup wizard listening` | `bind_addr` |

### プロキシログ

認証済みの upstream リクエストで以下を出力します:

| メッセージ | 重要フィールド |
|-----------|-------------|
| `proxy request` | `user`、`method`、`path`、`token_hash` |
| `proxy response` | `upstream_status`、`path` |
| `upstream rejected token; cache invalidated` | `path`、`token_hash` |

`token_hash` は `SHA-256(token)` の先頭 8 桁の 16 進数です。相関用であり、生トークン値はログに出力されません。

### 認証とセットアップログ

よく使われる認証とセットアップのメッセージ:

| メッセージ | 意味 |
|-----------|------|
| `auth failed` | Bearer トークン検証失敗 |
| `upstream error during auth` | プロバイダー検証が一時的な upstream エラーを返した |
| `token exchange rejected` | OAuth authorization-code 交換が無効だった |
| `refresh token rejected` | リフレッシュトークンが存在しない・期限切れ・使用済み |
| `token without audience accepted during grace period` | `token_audience_strict` 無効中に audience なし旧トークンが受け入れられた |
| `mcp-gateway starting in setup mode` | 必須設定が欠けている。`setup_url` に従ってください |
| `setup complete; restarting to apply configuration` | セットアップ POST が成功しプロセスがコード 0 で終了中 |

セットアップモードのログには `setup_url` と `token` が含まれます。トークンは短命のシークレットとして扱ってください。

### 便利なログコマンド

```bash
docker compose logs mcp-gateway | jq 'select(.msg=="http request")'
docker compose logs mcp-gateway | jq 'select(.level=="ERROR" or .level=="WARN")'
docker compose logs mcp-gateway | jq 'select(.msg=="proxy response" and .upstream_status>=500)'
```

`jq` が使えない場合は生ログを追跡します:

```bash
docker compose logs -f mcp-gateway
```

### OAuth 監査ログファイル

OAuth 監査イベントは stdout に加え、ローテーション付き JSON Lines ファイルへ保存されます。既定パスは Windows では `%LOCALAPPDATA%\mcp-gateway\logs\auth-audit.jsonl`、Linux では `$XDG_STATE_HOME/mcp-gateway/logs/auth-audit.jsonl` または `$HOME/.local/state/mcp-gateway/logs/auth-audit.jsonl`、macOS では `$HOME/Library/Logs/mcp-gateway/auth-audit.jsonl` です。公式コンテナイメージでは `/data/mcp-gateway/logs/auth-audit.jsonl` を使用します。

PowerShell:

```powershell
$path = Join-Path $env:LOCALAPPDATA 'mcp-gateway\logs\auth-audit.jsonl'
Get-Content -LiteralPath $path |
  ForEach-Object { $_ | ConvertFrom-Json } |
  Where-Object result -eq 'failure' |
  Select-Object timestamp, phase, provider, error_class, oauth_error, http_status
```

Linux / macOS / コンテナ:

```bash
jq 'select(.result == "failure") |
  {timestamp, phase, provider, error_class, oauth_error, http_status}' \
  /data/mcp-gateway/logs/auth-audit.jsonl
```

internal API が有効な場合は直近の失敗をAPIで取得できます。エンドポイントは既存のループバック + 共有シークレット境界を共有します。

```bash
curl -fsS \
  -H "Authorization: Bearer ${MCP_GATEWAY_INTERNAL_SECRET}" \
  "http://127.0.0.1:${MCP_GATEWAY_INTERNAL_PORT}/internal/v1/auth/failures?limit=20"
```

レスポンスは最新順で最大 100 件です。永続的な事後解析の正本は JSON Lines ファイルであり、internal API の履歴はプロセス再起動時に消失します。

## よくある問題

### `setup_required`

症状:

- `/setup` 以外のパスが `503 {"error":"setup_required","setup_url":"..."}` を返す
- ログに `mcp-gateway starting in setup mode` がある

原因:

- 必須値（GitHub クライアント ID・クライアントシークレット・少なくとも1つのルート）のいずれかが欠けている

対処:

1. ログの `setup_url` を開くか、`GET /setup?token=<TOKEN>` を実行する。
2. 欠けている `client_id`・`client_secret`・`routes` を POST する。
3. コード 0 で終了後にスーパーバイザーがゲートウェイを再起動するのを待つ。

### セットアップトークンの有効期限切れ

症状:

- `GET /setup?token=<TOKEN>` または `POST /setup?token=<TOKEN>` が `408` を返す

原因:

- セットアップトークンの有効期間は 15 分です。

対処:

1. 必須設定が欠けたままゲートウェイを再起動する。
2. stdout から新しい `setup_url` と `token` を読む。
3. セットアップリクエストを繰り返す。

### `gateway.key` が破損または読み取り不可

症状:

- トラフィックを処理する前に起動が終了する。
- ログに `failed to load gateway encryption key` がある。

原因:

- `gateway.key` が存在するが空・不正形式・読み取り不可。ゲートウェイは自動再生成を拒否します（`config.yaml` の暗号化シークレットが永久にアクセス不能になるリスクがあるため）。

対処:

1. バックアップから `gateway.key` を復元する。
2. キーが元々 `MCP_GATEWAY_MASTER_KEY` から導出されていた場合、破損したキーファイルを削除し同じマスターキーで再起動すると同一 identity が再生成されます。
3. バックアップもマスターキーも存在しない場合、`config.yaml` の暗号化 `auth.github_client_secret` を削除または置換し、`OAUTH_CLIENT_SECRET` を再度提供してゲートウェイに新しいキーで新しい暗号化値を書き込ませます（旧 `GITHUB_MCP_CLIENT_SECRET` も非推奨警告付きで受け入れられます）。

現在の暗号化 `config.yaml` を回復できる確信がない限り、`gateway.key` を最初の対処として削除しないでください。

### `github_client_secret is unavailable`

症状:

- 起動ログに `github_client_secret is unavailable` がある。

原因:

- `config.yaml` の `auth.github_client_secret` も `OAUTH_CLIENT_SECRET`（または旧 `GITHUB_MCP_CLIENT_SECRET`）も設定されていない。

対処:

- `OAUTH_CLIENT_SECRET` を一度提供してゲートウェイが暗号化・永続化できるようにするか、有効な暗号化 `auth.github_client_secret` と対応する `gateway.key` を復元してください。非推奨の `GITHUB_MCP_CLIENT_SECRET` は後方互換性のため引き続き受け入れられますが、起動時警告が出力されます。

### ルートが設定されていない

症状:

- 起動ログに `no routes configured: set ROUTE_<NAME>=<prefix>|<upstream_url>` がある。

対処:

- `ROUTE_<NAME>` 環境変数を少なくとも1つ設定するか、`config.yaml` に `routes:` エントリを追加してください。

例:

```bash
ROUTE_GITHUB=/mcp/github|http://github-mcp:8082
```

### Docker ポートが公開されているがゲートウェイに到達できない

症状:

- `docker compose ps` で公開ポートが表示されるが、ホストからのリクエストが失敗する。

原因:

- ゲートウェイがコンテナ内のループバックデフォルト（`127.0.0.1:8080`）にバインドされている。

対処:

```bash
MCP_GATEWAY_BIND_ADDR=0.0.0.0:8080
```

`MCP_GATEWAY_PUBLIC_URL` はブラウザから見える URL（例: `http://127.0.0.1:8080`）に設定したままにしてください。

### GitHub OAuth コールバック不一致

症状:

- GitHub が OAuth コールバック URL を拒否する。
- `/callback` に戻る前にブラウザ認証フローが失敗する。

対処:

GitHub OAuth App のコールバック URL を以下と完全一致するよう更新します:

```text
<MCP_GATEWAY_PUBLIC_URL>/callback
```

ローカルデフォルトの場合:

```text
http://127.0.0.1:8080/callback
```

### 状態ディレクトリを作成できない

症状:

- `go run ./cmd/server` またはベアバイナリで、状態ディレクトリ/トークンストアの作成または開放に失敗する（例: `permission denied`）。

対処:

ゲートウェイは起動時に OS デフォルトの状態ディレクトリを自動作成します。権限の問題などでディレクトリを作成できない場合は、書き込み可能な場所にパスを固定してください:

```bash
export MCP_GATEWAY_TOKEN_STORE_PATH=/your/writable/path/tokens.json
export MCP_CONFIG_FILE=/your/writable/path/config.yaml
export MCP_GATEWAY_KEY_PATH=/your/writable/path/gateway.key
```

### 無効な信頼済みプロキシ CIDR

症状:

- 起動ログに `invalid trusted proxy configuration` がある。

対処:

- `MCP_GATEWAY_TRUSTED_PROXIES` のすべてのエントリまたは `gateway.trusted_proxies` の各項目が `127.0.0.1/32` や `10.0.0.0/8` などの有効な CIDR 形式であることを確認してください。

### トークン audience 不一致

症状:

- 認証済みルートリクエストが `invalid_token` で 401 を返す。
- ログに audience 不一致またはレガシー audience 猶予期間受け入れの記録がある。

対処:

1. クライアントが `WWW-Authenticate.resource_metadata` URL に従っていることを確認する。
2. クライアントを再認証してルートリソース用のトークンを取得させる。
3. レガシー audience なしトークンがログから消えるまで `MCP_GATEWAY_TOKEN_AUDIENCE_STRICT=false` を維持する。

## bind_addr と public_url

mcp-gateway はリッスンアドレスと公開 URL を分離しています:

| 設定 | 環境変数 | YAML キー | デフォルト | 用途 |
|------|---------|---------|---------|------|
| バインドアドレス | `MCP_GATEWAY_BIND_ADDR` | `gateway.bind_addr` | `127.0.0.1:8080` | HTTP サーバーがリッスンするネットワークインターフェースとポート |
| 公開 URL | `MCP_GATEWAY_PUBLIC_URL` | `gateway.public_url` | `http://127.0.0.1:8080` | OAuth コールバック・ディスカバリメタデータ・PRM で使用する正規 URL |

v0.3.0 以前は `MCP_GATEWAY_BASE_URL` / `gateway.base_url` が公開 URL のみを制御していました。サーバーはその設定に関わらず常にすべてのインターフェース（`:<port>`）でリッスンしていました。旧設定は非推奨になり将来のリリースで削除されます。

### 分離が重要な理由

Docker デプロイではゲートウェイが `0.0.0.0:8080` にバインドしてホストがポートフォワーディング経由で到達できるようにしますが、GitHub に登録する OAuth コールバック URL はユーザーのブラウザが到達できるアドレスである必要があります。ローカル開発では通常 `http://127.0.0.1:8080` です。

### MCP_GATEWAY_BASE_URL からの移行

環境変数を更新します:

| 旧 | 新 |
|----|-----|
| `MCP_GATEWAY_BASE_URL=http://localhost:<port>` | `MCP_GATEWAY_PUBLIC_URL=http://127.0.0.1:<port>` |
| すべてのインターフェースへの暗黙的バインド `:<port>` | ローカル実行: `MCP_GATEWAY_BIND_ADDR=127.0.0.1:<port>`、Docker: `0.0.0.0:<port>` |

`config.yaml` を使用している場合は更新します:

```yaml
# 変更前
gateway:
  base_url: "http://localhost:<port>"

# 変更後
gateway:
  public_url: "http://127.0.0.1:<port>"
  bind_addr: "127.0.0.1:<port>"
```

GitHub OAuth App のコールバック URL を更新します:

| フィールド | 旧値 | 新値 |
|-----------|------|------|
| Authorization callback URL | `http://localhost:<port>/callback` | `http://127.0.0.1:<port>/callback` |

GitHub はコールバック URL を完全一致で検証するため、登録値はゲートウェイが送信する URL と一致する必要があります。

### 切り替え手順

1. 更新したゲートウェイのバイナリまたはイメージをデプロイする。
2. GitHub OAuth App のコールバック URL を更新する。
3. `docker-compose.yml`・systemd ユニット・`.env` を新しい変数に更新する。
4. ゲートウェイを再起動する。
5. `/health` が `{"status":"ok"}` を返すことを確認する。

トークンストアが削除されていないか、プロバイダーが upstream トークンを失効させていない限り、既存のアクセストークンとリフレッシュトークンは引き続き有効です。

## リバースプロキシデプロイ

mcp-gateway の前で TLS を終端する場合は、公開 URL を外部オリジンに設定し、直前のプロキシ CIDR のみを信頼します:

```bash
MCP_GATEWAY_PUBLIC_URL=https://mcp.example.com
MCP_GATEWAY_BIND_ADDR=127.0.0.1:8080
MCP_GATEWAY_TRUSTED_PROXIES=127.0.0.1/32,10.0.0.0/8
```

同等の `config.yaml`:

```yaml
gateway:
  public_url: "https://mcp.example.com"
  bind_addr: "127.0.0.1:8080"
  trusted_proxies:
    - "127.0.0.1/32"
    - "10.0.0.0/8"
```

直前のピア IP が `trusted_proxies` に一致する場合、mcp-gateway は以下を反映します:

| ヘッダー | 反映されるリクエストフィールド |
|---------|---------------------------|
| `X-Forwarded-Proto` | `r.URL.Scheme`（値が `http` または `https` の場合のみ） |
| `X-Forwarded-Host` | 基本的なホスト検証後の `r.Host` |
| `X-Forwarded-For` | 信頼済みプロキシが提供する最右端の有効 IP を使用した `r.RemoteAddr` |

ピアが信頼されていない場合、`Forwarded`・`X-Forwarded-*`・`X-Real-IP` は後続のミドルウェアとハンドラの実行前にすべて除去されます。

クライアントが提供した値をそのまま渡すのではなく、リバースプロキシが `X-Forwarded-For` を上書きまたはサニタイズするよう設定してください。ゲートウェイは追記されたスプーフィングエントリへの防御として右端からヘッダーを読みますが、プロキシ側でこのヘッダーを管理すべきです。

nginx の location 設定例:

```nginx
location / {
    proxy_set_header Host $host;
    proxy_set_header X-Forwarded-Host $host;
    proxy_set_header X-Forwarded-Proto $scheme;
    proxy_set_header X-Forwarded-For $remote_addr;
    proxy_pass http://127.0.0.1:8080;
}
```

`MCP_GATEWAY_PUBLIC_URL` は OAuth・ディスカバリ・PRM の正規 URL のままです。クライアントが使用する外部オリジンと同じ値に保つようにしてください。
