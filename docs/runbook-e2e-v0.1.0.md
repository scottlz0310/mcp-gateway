# v0.1.0 E2E 動作検証ランブック

`mcp-gateway` v0.1.0 リリース後の E2E 動作検証手順。
v0.1.0 で追加された **設定永続化（age 暗号化）**・**Setup Wizard**・**トークン永続化**・**ルーティング**・**OAuth 各種フロー**を実環境（Docker Compose）で踏破することを目的とする。

> **対象タグ**: `v0.1.0`（コミット `dd6de92` 以降のメインブランチでも可）
> **想定実行者**: メンテナ本人
> **所要時間**: 60〜90 分（GitHub OAuth のブラウザ往復を含む）
> **作成日**: 2026-05-05

---

## 1. 検証スコープと合格基準

### スコープ

| 領域 | 検証する項目 |
|---|---|
| Config 永続化 | `config.yaml` への secret 暗号化保存、再起動後の復号 |
| Key management | `gateway.key` 自動生成・破損検知・`MCP_GATEWAY_MASTER_KEY` 決定論的導出 |
| Setup Wizard | 初回起動時の `503 setup_required`、`/setup` 経由の config 投入、再起動後の通常起動 |
| OAuth | Authorization Code + PKCE、Refresh Token、Device Authorization Grant |
| Token persistence | `/data/tokens.json` 経由の認証スキップ（再起動後） |
| Routing | longest-prefix match、`auth=none` バイパス |
| エラー応答 | RFC 6750 / RFC 9728 に沿った 401 / `WWW-Authenticate` |
| 結合 | `copilot-review-mcp` との `AUTH_MODE=gateway` 連携 |

### スコープ外

- 負荷テスト・パフォーマンス計測
- セキュリティ監査（gosec / govulncheck などは v0.2.0-RM3 で別途）
- HTTPS 終端（リバースプロキシ／Caddy 等は本ランブック外）
- fly.io デプロイ（保留中の #4 で対応予定）

### 合格基準

- すべての必須シナリオ（§4.1〜§4.10）が **観測された挙動 = 期待挙動** で完了
- ログに以下が **一切出力されていない** こと:
  - GitHub OAuth client secret の平文値
  - `ENC[age:]...` の全文
  - `gateway.key` の内容
  - 任意の Bearer token の生値
- 失敗・回帰があった場合は §6 の手順で issue 化

---

## 2. 前提条件

### 必要なツール

| ツール | 用途 | 推奨バージョン |
|---|---|---|
| Docker / Docker Compose | gateway + upstream の起動 | 24+ / v2 |
| `curl` | HTTP リクエスト | 任意 |
| `jq` | JSON パース | 任意 |
| `openssl` | `MCP_GATEWAY_MASTER_KEY` / PKCE 値の生成 | 任意（PowerShell 代替可） |
| ブラウザ | Authorization Code Flow の手動承認 | 任意 |
| `age-keygen`（任意） | `gateway.key` の互換性確認 | 1.1+ |

### 必要な事前準備

1. GitHub App を用意し、検証対象リポジトリの owner account にインストールする
   - `AUTH_MODE=gateway` で検証する場合は gateway 用 1 つでよい
   - `copilot-review-mcp` の standalone モードも併せて検証する場合のみ、copilot-review-mcp 用に 2 つ目を用意する
   - 用途を分けるためアプリは分離してもよいが、同一アプリでも検証は可能
   - Authorization callback URLs: `http://localhost:8080/callback` と `http://localhost:8080/device_callback`
   - Device Flow を有効化
   - installation token 用 private key を生成し、安全な場所へ保存する
2. `examples/copilot-review-routing/` をコピーして作業ディレクトリを作る
   ```bash
   cp -r examples/copilot-review-routing /tmp/mcp-gateway-e2e
   cd /tmp/mcp-gateway-e2e
   ```
3. `.env` を作成（`.env.example` があればそれをベースに、無ければ次の最小構成）
   ```env
   OAUTH_CLIENT_ID=Iv23liXXXXXXXXXX
   OAUTH_CLIENT_SECRET=__leave_empty_for_wizard_test__
   GITHUB_APP_ID=123456
   GITHUB_APP_INSTALLATION_ID=12345678
   GITHUB_APP_PRIVATE_KEY_PATH=/run/secrets/github-app-private-key.pem
   COPILOT_REVIEW_AUTH_MODE=gateway
   GITHUB_CLIENT_ID=
   GITHUB_CLIENT_SECRET=
   ROUTE_GITHUB=/mcp/github|http://github-mcp:8082|upstream_github_app=true
   MCP_GATEWAY_BASE_URL=http://localhost:8080
   ```
4. `data/` ディレクトリを volume mount 用に作成
   ```bash
   mkdir -p data
   ```
5. `docker-compose.yml` の `mcp-gateway` サービスに永続化設定があることを確認する（現行の `examples/copilot-review-routing/` には設定済み。古いコピーを使う場合は以下を追記）
   ```yaml
       volumes:
         - ./data:/data
       environment:
         MCP_GATEWAY_KEY_PATH: /data/gateway.key
         MCP_CONFIG_FILE: /data/config.yaml
         MCP_GATEWAY_TOKEN_STORE_PATH: /data/tokens.json
   ```
6. `copilot-review-mcp` サービスに gateway mode が設定されていることを確認する
   ```yaml
      AUTH_MODE: ${COPILOT_REVIEW_AUTH_MODE:-gateway}
   ```

---

## 3. 検証実行のルール

- **シナリオは原則順序通りに実行する**。前段の状態（`gateway.key`・`config.yaml`・`tokens.json`）を後段が利用するため。
- 各シナリオの末尾に「**観測された挙動**」欄を設け、合致／差分を記録する。
- 期待と異なる挙動を観測した場合は中断し、§6 のテンプレートで issue を切る。
- 検証中はログを `docker compose logs -f mcp-gateway` で常時 follow しておく。
- シナリオを途中からやり直す場合は §7 の「クリーンアップ」を参照。

### Windows Defender / セキュリティソフトの誤検知

本ランブックでは PowerShell / Docker Compose / `curl` を用いて、OAuth client secret、`gateway.key`、`tokens.json`、`auth=none` ルートなどを扱う。
そのため Windows Defender 等が `Trojan:PowerShell`、`Behavior:Win32`、`AMSI` 系の検出名で E2E 実行コマンドを誤検知する場合がある。

検出された場合は、除外設定を行う前に以下を確認する。

- 検出対象が本リポジトリ配下または E2E 用作業ディレクトリであること
- 検出対象が `pwsh.exe -Command ...` の E2E 実行コマンド、または本ランブックの手順で生成した一時スクリプトであること
- ログや生成ファイルに実 token / secret / `gateway.key` の生値が出力されていないこと

実際に Codex の自律確認で Defender が反応したコマンドラインは、長い inline PowerShell が `docker compose` 用の一時 YAML を生成し、`mcp-gateway:e2e-local` を `mcpgw-e2e-<port>` project 名で起動するものだった。
このケースでは以下が一致していれば、本ランブック由来の一時検証である可能性が高い。

- `pwsh.exe -Command` の中で `$root = Join-Path $env:TEMP ("mcp-gateway-e2e-codex-" + ...)` を作成している
- Docker Compose project 名が `mcpgw-e2e-<port>` 形式
- gateway image が `mcp-gateway:e2e-local`
- secret 値が `dummy-secret-for-e2e` で、実 OAuth secret / PAT / Bearer token ではない
- HTTP アクセス先が `localhost:<port>` の一時 gateway

同種の自律確認を再実行する場合は、長い `pwsh.exe -Command ...` を直接実行するより、E2E 用作業ディレクトリ配下に確認用 `.ps1` を置いて内容を確認してから実行する。
実 secret / PAT / Bearer token がコマンドライン、ログ、`docker compose config` 出力、PowerShell history、Defender 検出詳細のいずれかに含まれていた場合は、その値を漏えい扱いとして即座にローテーションする。

除外設定を行う場合は、`TEMP` 全体や `pwsh.exe` ではなく、E2E 用作業ディレクトリなど最小範囲に限定する。

---

## 4. 検証シナリオ

### 4.1 First-run Setup Wizard

**目的**: `config.yaml` も env vars も不足する状態から `/setup` 経由で初期化できることを確認する。

#### 手順

1. `data/` を空にする
   ```bash
   rm -f data/gateway.key data/config.yaml data/tokens.json data/tokens.json.refresh
   ```
2. `.env` から secret 系を一時的に空にする
   ```env
   GITHUB_MCP_CLIENT_ID=
   GITHUB_MCP_CLIENT_SECRET=
   ```
   `docker-compose.yml` の `ROUTE_GITHUB` / `ROUTE_COPILOT_REVIEW` も一時的にコメントアウトする（routes も空状態を作る）。
3. 起動
   ```bash
   docker compose up -d mcp-gateway
   docker compose logs -f mcp-gateway
   ```
4. ログで setup token を取得
   ```
   {"level":"warn","msg":"mcp-gateway starting in setup mode — configure via /setup",
    "setup_url":"http://localhost:8080/setup?token=<TOKEN>","token":"<TOKEN>"}
   ```
5. 通常ルートが 503 を返すことを確認
   ```bash
   curl -i http://localhost:8080/mcp/github
   # 期待: HTTP/1.1 503 Service Unavailable
   #       {"error":"setup_required","setup_url":"http://localhost:8080/setup?token=..."}
   ```
6. `GET /setup` で不足項目を確認
   ```bash
   curl "http://localhost:8080/setup?token=<TOKEN>"
   # 期待: {"missing":["client_id","client_secret","routes"], ...}
   ```
7. `POST /setup` で設定を投入
   ```bash
   curl -X POST "http://localhost:8080/setup?token=<TOKEN>" \
     -H "Content-Type: application/json" \
     -d '{
       "client_id": "Ov23liXXXXXXXXXX",
       "client_secret": "your-real-github-oauth-secret",
       "routes": [
         {"name": "github", "prefix": "/mcp/github", "upstream": "http://github-mcp:8082"},
         {"name": "copilot_review", "prefix": "/mcp/copilot-review", "upstream": "http://copilot-review-mcp:8083"}
       ]
     }'
   # 期待: {"saved":true,"restart_required":true}
   ```
8. gateway が exit code 0 で停止し、`restart: unless-stopped` で再起動することを確認

#### 期待される挙動

- [ ] `data/gateway.key` が新規生成され、`AGE-SECRET-KEY-1...` で始まるテキストファイルである
- [ ] `data/config.yaml` の `auth.github_client_secret` が `ENC[age:]<base64>` 形式
- [ ] `data/config.yaml` に `routes:` ブロックが書き込まれている
- [ ] `data/config.yaml` の `setup.completed: true` が記録されている
- [ ] 再起動後は通常モードで起動し、setup token のログが出ない
- [ ] ログに client_secret の平文が含まれない
- [ ] `gateway.key` のパーミッションが `0600`（Linux/macOS）

#### 観測された挙動

```
（実行時に記入）
```

---

### 4.2 Config 暗号化往復（再起動を跨いだ persist）

**目的**: 暗号化された `github_client_secret` が再起動後も復号でき、ログに平文が出ないことを確認する。

#### 手順

1. §4.1 完了状態から開始
2. `data/config.yaml` を読み、`ENC[age:]...` で始まる行があることを確認
   ```bash
   grep -E "^\s*github_client_secret:" data/config.yaml
   # 期待: github_client_secret: "ENC[age:]<base64>..."
   ```
3. `.env` の `GITHUB_MCP_CLIENT_SECRET` は空のまま gateway を再起動
   ```bash
   docker compose restart mcp-gateway
   ```
4. ログにエラーが無いこと、setup mode に入っていないことを確認
5. 認証不要の discovery エンドポイントが 200 で応答することを確認（secret が config から読み込まれていることの間接確認 — 失敗時は setup mode 突入や startup error が起きる）
   ```bash
   curl -i http://localhost:8080/.well-known/oauth-authorization-server
   # 期待: 200 OK + JSON metadata（issuer/authorization_endpoint/token_endpoint 等）
   ```
6. 認証必須ルートが Bearer 無しで 401 を返すこと（auth middleware が活きていることの確認）
   ```bash
   curl -i http://localhost:8080/mcp/github
   # 期待: 401 Unauthorized + WWW-Authenticate: Bearer ...
   ```

#### 期待される挙動

- [ ] 再起動後 setup mode に **入らない**
- [ ] `/.well-known/oauth-authorization-server` が 200 を返す
- [ ] `/mcp/github` が Bearer 無しで 401 を返す
- [ ] ログに `ENC[age:]...` 全文・client_secret 平文が出ていない
- [ ] `data/config.yaml` の中身に変化がない（再書き込みされていない）

#### 観測された挙動

```
（実行時に記入）
```

---

### 4.3 gateway.key 破損時の起動失敗

**目的**: `gateway.key` が壊れている／空のとき、自動上書きせず明示的に起動失敗することを確認する（運用事故防止）。

#### 手順

1. gateway を停止
   ```bash
   docker compose stop mcp-gateway
   ```
2. `gateway.key` をバックアップしてから空にする
   ```bash
   cp data/gateway.key data/gateway.key.bak
   : > data/gateway.key
   ```
3. 起動
   ```bash
   docker compose up -d mcp-gateway
   docker compose logs mcp-gateway
   ```
4. 起動が失敗していること（exit code 非 0）を確認
   ```bash
   docker compose ps mcp-gateway
   # 期待: STATUS が Exited (1) もしくは類似
   ```
5. ログに以下のようなメッセージが出ていることを確認
   ```
   failed to load gateway encryption key
   gateway.key is corrupt or unreadable
   ```
6. バックアップを書き戻して復旧
   ```bash
   mv data/gateway.key.bak data/gateway.key
   docker compose up -d mcp-gateway
   ```

#### 期待される挙動

- [ ] 空ファイル状態で起動が失敗（exit code 1）
- [ ] `gateway.key` が **自動再生成されない**（ファイルサイズが 0 のままか、バックアップ前の状態を保持）
- [ ] ログにキー内容が出力されていない

#### 観測された挙動

```
（実行時に記入）
```

---

### 4.4 MCP_GATEWAY_MASTER_KEY 決定論的導出

**目的**: `gateway.key` を消した状態で `MCP_GATEWAY_MASTER_KEY` を与えると、同じキーが再生成されることを確認する。

> **重要**: `MCP_GATEWAY_MASTER_KEY` は「同じ master key で生成された `gateway.key`」を復元するためのもの。
> §4.1 を master key 無しで実行した場合、`config.yaml` はランダム生成された `gateway.key` で暗号化されている。
> その後で新しい `MCP_GATEWAY_MASTER_KEY` を設定しても、既存の `ENC[age:]...` は復号できない。
> このシナリオでは §4.1 の状態をバックアップし、まず決定論的導出だけを確認する。
> 「暗号化済み config の復号」まで確認する場合は、後述の追加検証のように master key を最初から設定した状態で config を作り直す。

#### 手順

1. gateway を停止し、現在の `gateway.key` / `config.yaml` を退避してから削除する
   ```bash
   docker compose stop mcp-gateway
   cp data/gateway.key /tmp/gateway.key.original
   cp data/config.yaml /tmp/config.yaml.original
   rm data/gateway.key
   rm data/config.yaml
   ```
2. `MCP_GATEWAY_MASTER_KEY` を生成し `.env` にセット
   ```bash
   echo "MCP_GATEWAY_MASTER_KEY=$(openssl rand -hex 32)" >> .env
   ```
   PowerShell で `openssl` が無い場合:
   ```powershell
   $bytes = [byte[]]::new(32)
   [System.Security.Cryptography.RandomNumberGenerator]::Fill($bytes)
   "MCP_GATEWAY_MASTER_KEY=$([Convert]::ToHexString($bytes).ToLower())" | Add-Content .env
   ```
3. `docker-compose.yml` で `MCP_GATEWAY_MASTER_KEY: ${MCP_GATEWAY_MASTER_KEY}` を有効化
4. 起動
   ```bash
   docker compose up -d mcp-gateway
   ```
5. `data/gateway.key` が生成されたことを確認し、内容を一時保存
   ```bash
   cp data/gateway.key /tmp/gateway.key.derived1
   ```
6. もう一度キーを削除して再起動
   ```bash
   docker compose stop mcp-gateway
   rm data/gateway.key
   docker compose up -d mcp-gateway
   ```
7. 再生成された `gateway.key` が `/tmp/gateway.key.derived1` と完全一致することを確認
   ```bash
   diff data/gateway.key /tmp/gateway.key.derived1
   # 期待: 出力なし（一致）
   ```
8. バックアップした元の `gateway.key` / `config.yaml` を戻し、`MCP_GATEWAY_MASTER_KEY` を無効化して通常状態へ復旧する
   ```bash
   docker compose stop mcp-gateway
   mv /tmp/gateway.key.original data/gateway.key
   mv /tmp/config.yaml.original data/config.yaml
   # .env または docker-compose.yml から MCP_GATEWAY_MASTER_KEY の有効化を戻す
   docker compose up -d mcp-gateway
   ```
9. 通常起動できることを確認
   ```bash
   curl -i http://localhost:8080/.well-known/oauth-authorization-server
   # 期待: 200 OK
   ```

#### 追加検証: master key 由来 config の復号

`MCP_GATEWAY_MASTER_KEY` から再生成した `gateway.key` で `ENC[age:]...` を復号できることまで確認する場合は、別の作業ディレクトリまたは `data/` の完全バックアップを取ったうえで次を実行する。

1. `MCP_GATEWAY_MASTER_KEY` を有効化した状態で `data/` を空にする
2. §4.1 Setup Wizard を再実行し、`config.yaml` を master key 由来の `gateway.key` で暗号化保存する
3. gateway を停止し、`data/gateway.key` だけを削除する
4. 同じ `MCP_GATEWAY_MASTER_KEY` のまま起動する
5. `/.well-known/oauth-authorization-server` が 200 を返すことを確認する

#### 期待される挙動

- [ ] 同じ `MCP_GATEWAY_MASTER_KEY` から毎回同じ `gateway.key` が生成される
- [ ] master key 由来の `gateway.key` で暗号化した `ENC[age:]...` は、同じ master key から再生成したキーで復号できる
- [ ] `MCP_GATEWAY_MASTER_KEY` が 32 bytes 未満の場合は起動失敗（追加検証として `MCP_GATEWAY_MASTER_KEY=short` で起動して確認）

#### 観測された挙動

```
（実行時に記入）
```

---

### 4.5 Authorization Code Flow（ブラウザ経由）

**目的**: ブラウザ経由の OAuth 2.0 + PKCE が成立し、Bearer token が発行されることを確認する。

#### 手順

1. 通常起動状態に戻す（§4.4 まで終わっていれば OK）
2. PKCE 用の `code_verifier` / `code_challenge` を base64url で生成（RFC 7636 §4.1 / §4.2）
   ```bash
   # base64url-safe: '+' → '-', '/' → '_', パディング '=' を削除
   CODE_VERIFIER=$(openssl rand -base64 32 | tr '+/' '-_' | tr -d '=')
   CODE_CHALLENGE=$(printf '%s' "$CODE_VERIFIER" | openssl dgst -sha256 -binary | base64 | tr '+/' '-_' | tr -d '=')
   echo "verifier=$CODE_VERIFIER (len=${#CODE_VERIFIER})"   # 期待: 43 文字（範囲 43〜128 内）
   echo "challenge=$CODE_CHALLENGE (len=${#CODE_CHALLENGE})"
   ```
   PowerShell で `openssl` が無い場合:
   ```powershell
   $bytes = [byte[]]::new(32)
   [System.Security.Cryptography.RandomNumberGenerator]::Fill($bytes)
   $CODE_VERIFIER = [Convert]::ToBase64String($bytes).TrimEnd('=').Replace('+','-').Replace('/','_')
   $hash = [System.Security.Cryptography.SHA256]::HashData([Text.Encoding]::ASCII.GetBytes($CODE_VERIFIER))
   $CODE_CHALLENGE = [Convert]::ToBase64String($hash).TrimEnd('=').Replace('+','-').Replace('/','_')
   "verifier=$CODE_VERIFIER (len=$($CODE_VERIFIER.Length))"
   "challenge=$CODE_CHALLENGE (len=$($CODE_CHALLENGE.Length))"
   ```
3. ブラウザで `/authorize` を開く
   ```
   http://localhost:8080/authorize?response_type=code&client_id=mcp-client&redirect_uri=http://localhost:8080/callback&code_challenge=<CODE_CHALLENGE>&code_challenge_method=S256&state=test123
   ```
4. GitHub の承認画面で許可 → callback で `code` パラメータを受領
5. `/token` で code を交換
   ```bash
   curl -X POST http://localhost:8080/token \
     -d "grant_type=authorization_code" \
     -d "code=<CODE>" \
     -d "redirect_uri=http://localhost:8080/callback" \
     -d "client_id=mcp-client" \
     -d "code_verifier=$CODE_VERIFIER"
   # 期待: {"access_token":"...","token_type":"Bearer","expires_in":7776000,"refresh_token":"..."}
   ```
6. 取得した access_token を保存
   ```bash
   ACCESS=<access_token>
   REFRESH=<refresh_token>
   ```

#### 期待される挙動

- [ ] `/authorize` が GitHub の承認画面にリダイレクトされる
- [ ] callback 後に `code` が発行される
- [ ] `/token` が `access_token` + `refresh_token` を返す
- [ ] ログに access_token / refresh_token の生値が **含まれない**

#### 観測された挙動

```
（実行時に記入）
```

---

### 4.6 ルーティング & ヘッダ注入

**目的**: longest-prefix match と `X-Authenticated-User` ヘッダ注入が成立することを確認する。

#### 手順

1. §4.5 で取得した `$ACCESS` を使い、`/mcp/github` に MCP initialize リクエストを送る
   ```bash
   MCP_INIT='{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"mcp-gateway-e2e","version":"0.0.1"}}}'
   curl -i -X POST http://localhost:8080/mcp/github \
     -H "Authorization: Bearer $ACCESS" \
     -H "Content-Type: application/json" \
     -H "Accept: application/json, text/event-stream" \
     --data "$MCP_INIT"
   # 期待: 200 OK（github-mcp の応答）
   ```
2. `/mcp/copilot-review` も同様に確認
   ```bash
   curl -i -X POST http://localhost:8080/mcp/copilot-review \
     -H "Authorization: Bearer $ACCESS" \
     -H "Content-Type: application/json" \
     -H "Accept: application/json, text/event-stream" \
     --data "$MCP_INIT"
   ```
3. gateway のログから upstream へ `X-Authenticated-User` / `X-GitHub-Login` が注入されていることを確認
   - upstream 側ログ（`docker compose logs github-mcp` など）でも、これらのヘッダが見えるはず

#### 期待される挙動

- [ ] `/mcp/github` → `github-mcp:8082` にルーティングされる
- [ ] `/mcp/copilot-review` → `copilot-review-mcp:8083` にルーティングされる
- [ ] upstream へ `X-Authenticated-User: <github-login>` が注入される
- [ ] Bearer 無し / 無効 token は 401 を返す
  ```bash
  curl -i http://localhost:8080/mcp/github/
  # 期待: 401 Unauthorized + WWW-Authenticate: Bearer realm="..." resource_metadata="..."
  ```

#### 観測された挙動

```
（実行時に記入）
```

---

### 4.7 Refresh Token Grant

**目的**: `refresh_token` grant でアクセストークンを再発行できることを確認する。

#### 手順

1. §4.5 の `$REFRESH` を使う
   ```bash
   curl -X POST http://localhost:8080/token \
     -d "grant_type=refresh_token" \
     -d "refresh_token=$REFRESH" \
     -d "client_id=mcp-client"
   # 期待: {"access_token":"...","token_type":"Bearer","expires_in":...,"refresh_token":"<NEW>"}
   ```
2. 旧 refresh_token が **無効化されている**ことを確認
   ```bash
   curl -X POST http://localhost:8080/token \
     -d "grant_type=refresh_token" \
     -d "refresh_token=$REFRESH" \
     -d "client_id=mcp-client"
   # 期待: 400 invalid_grant
   ```
3. 新しく発行された refresh_token を保存して以降の検証に使う

#### 期待される挙動

- [ ] 新しい access_token が発行される
- [ ] refresh_token もローテーションされる（新しい値が返る）
- [ ] 旧 refresh_token は再使用不可
- [ ] `data/tokens.json.refresh` が更新されている

#### 観測された挙動

```
（実行時に記入）
```

---

### 4.8 Token persistence（再起動後の認証スキップ）

**目的**: `/data/tokens.json` 経由で gateway 再起動後も認証が引き継がれることを確認する。

#### 手順

1. §4.7 完了直後の `$ACCESS` を保持
2. gateway を再起動
   ```bash
   docker compose restart mcp-gateway
   ```
3. 再起動後すぐに同じ access_token で `/mcp/github` に MCP initialize リクエストを送る
   ```bash
   MCP_INIT='{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"mcp-gateway-e2e","version":"0.0.1"}}}'
   curl -i -X POST http://localhost:8080/mcp/github \
     -H "Authorization: Bearer $ACCESS" \
     -H "Content-Type: application/json" \
     -H "Accept: application/json, text/event-stream" \
     --data "$MCP_INIT"
   # 期待: 200 OK（再認証なし）
   ```
4. token store がハッシュ化された token key のみを含むことを確認
   ```bash
   cat data/tokens.json | jq '.'
   # 期待: token 値の生形ではなく、SHA-256 ハッシュキーが格納されている
   ```
   `MCP_GATEWAY_TOKEN_STORE_PATH` を `tokens.db` などに変更している場合は、その実ファイル名を確認する。

#### 期待される挙動

- [ ] 再起動後も既存 access_token が有効
- [ ] token store ファイルは `0600` パーミッション
- [ ] token store に raw token 文字列が **含まれない**（hashed key のみ）
- [ ] refresh token store（例: `tokens.json.refresh`）が存在し、`0600` パーミッション

#### 観測された挙動

```
（実行時に記入）
```

---

### 4.9 Device Authorization Grant

**目的**: RFC 8628 device flow が並列リクエストでも `slow_down` 無く成立することを確認する。

#### 手順

1. device 認可開始（レスポンスを変数に保存して device_code / verification_uri を取り出す）
   ```bash
   DEVICE_RESP=$(curl -s -X POST http://localhost:8080/device_authorization \
     -d "client_id=mcp-client" \
     -d "scope=repo user")
   echo "$DEVICE_RESP" | jq .
   DEVICE_CODE=$(echo "$DEVICE_RESP" | jq -r .device_code)
   USER_CODE=$(echo "$DEVICE_RESP" | jq -r .user_code)
   VERIFY_URI=$(echo "$DEVICE_RESP" | jq -r '.verification_uri_complete // .verification_uri')
   echo "open in browser: $VERIFY_URI (user_code=$USER_CODE)"
   # 期待: device_code/user_code/verification_uri/interval が取れていること
   ```
2. ブラウザで `$VERIFY_URI` を開き、`$USER_CODE` を入力して承認
3. 承認待ち中に **同じ device_code で並列に 5 回 token endpoint を叩く**
   ```bash
   for i in 1 2 3 4 5; do
     curl -s -X POST http://localhost:8080/token \
       -d "grant_type=urn:ietf:params:oauth:grant-type:device_code" \
       -d "device_code=$DEVICE_CODE" \
       -d "client_id=mcp-client" &
   done
   wait
   # 期待: 全リクエストが authorization_pending を返し、うち並列で in-flight に
   #       後着したものは error_description="polling in progress, please retry" を含む。
   #       slow_down は 1 件も返らない（直列化されているため GitHub への同時 polling が起きていない）。
   ```
4. 承認後に再度 `/token` を叩いて access_token を受領

#### 期待される挙動

- [ ] 並列ポーリングしても `slow_down` が **1 件も返らない**
- [ ] 並列リクエストのうち、in-flight 1 件は GitHub へ転送され、残りは即時に `authorization_pending` + `error_description="polling in progress, please retry"` を返す（gateway 側の直列化が機能している証跡）
- [ ] 承認後に正常に `access_token` が発行される

#### 観測された挙動

```
（実行時に記入）
```

---

### 4.10 per-route auth bypass（auth=none）

**目的**: `ROUTE_<NAME>=...|auth=none` で特定ルートの Bearer 検証がスキップされることを確認する。

#### 手順

1. `docker-compose.yml` に検証用の auth=none ルートを追加
   ```yaml
       ROUTE_PUBLIC_MCP: /public-mcp|http://github-mcp:8082|auth=none
   ```
   または既存の `auth=none` MCP upstream を流用する。
2. gateway を再起動
3. Bearer 無しで MCP initialize リクエストを送る
   ```bash
   MCP_INIT='{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"mcp-gateway-e2e","version":"0.0.1"}}}'
   curl -i -X POST http://localhost:8080/public-mcp \
     -H "Content-Type: application/json" \
     -H "Accept: application/json, text/event-stream" \
     --data "$MCP_INIT"
   # 期待: 200 OK（401 ではない）
   ```
4. 通常ルートは Bearer 無しで 401 になることを確認
   ```bash
   curl -i http://localhost:8080/mcp/github
   # 期待: 401 Unauthorized
   ```
5. 検証後はテスト用ルートをコメントアウトして元に戻す

#### 期待される挙動

- [ ] `auth=none` ルートは Bearer 無しで通る
- [ ] 同時に動いている他のルートは Bearer 検証が有効

#### 観測された挙動

```
（実行時に記入）
```

---

### 4.11 RFC 6750 / RFC 9728 エラー応答（任意）

**目的**: Bearer 不正時の `WWW-Authenticate` ヘッダが仕様に沿っていることを確認する。

#### 手順

1. 不正な token でアクセス
   ```bash
   curl -i -H "Authorization: Bearer invalid" \
     http://localhost:8080/mcp/github
   ```
2. レスポンスヘッダを確認
   ```
   HTTP/1.1 401 Unauthorized
   WWW-Authenticate: Bearer realm="...", error="invalid_token", resource_metadata="..."
   ```

#### 期待される挙動

- [ ] `WWW-Authenticate` ヘッダが存在
- [ ] `error="invalid_token"` を含む
- [ ] `resource_metadata` URL が含まれる（RFC 9728）

#### 観測された挙動

```
（実行時に記入）
```

---

## 5. 結果サマリ

| シナリオ | 結果 | 備考 |
|---|---|---|
| 4.1 Setup Wizard | ☐ Pass / ☐ Fail | |
| 4.2 Config 暗号化往復 | ☐ Pass / ☐ Fail | |
| 4.3 gateway.key 破損時 | ☐ Pass / ☐ Fail | |
| 4.4 MASTER_KEY 決定論性 | ☐ Pass / ☐ Fail | |
| 4.5 Authorization Code | ☐ Pass / ☐ Fail | |
| 4.6 Routing & ヘッダ注入 | ☐ Pass / ☐ Fail | |
| 4.7 Refresh Token | ☐ Pass / ☐ Fail | |
| 4.8 Token persistence | ☐ Pass / ☐ Fail | |
| 4.9 Device Grant 並列 | ☐ Pass / ☐ Fail | |
| 4.10 auth=none bypass | ☐ Pass / ☐ Fail | |
| 4.11 WWW-Authenticate | ☐ Pass / ☐ Fail | |

**最終判定**: ☐ v0.2.0 リリース可 / ☐ 修正後再検証

---

## 6. 失敗時のフロー

1. シナリオを中断し、再現手順を最小化する
2. 期待挙動と観測挙動の差分をシナリオの「観測された挙動」欄に記録
3. GitHub issue を以下のテンプレートで切る
   ```
   タイトル: bug(e2e): <シナリオ番号> <症状の要約>

   ## 再現手順
   - ランブック: docs/runbook-e2e-v0.1.0.md §<番号>
   - <最小再現手順>

   ## 期待
   - <ランブックの期待挙動>

   ## 観測
   - <実際に起きたこと>

   ## 環境
   - mcp-gateway: <commit hash>
   - Docker: <version>
   - OS: <version>
   ```
4. 修正 PR をマージしたらランブックを最初から再実行（前段の状態に依存するため）

---

## 7. クリーンアップ・再実行

### 全状態をリセットして最初からやり直す

```bash
docker compose down
rm -rf data/
mkdir -p data/
docker compose up -d
```

### setup wizard だけやり直す

```bash
docker compose stop mcp-gateway
rm data/config.yaml
# gateway.key は残してよい（残せば暗号化キーは保持される）
docker compose up -d mcp-gateway
```

### token state だけリセットする（強制再認証）

```bash
docker compose stop mcp-gateway
rm -f data/tokens.json data/tokens.json.refresh
docker compose up -d mcp-gateway
```

---

## 8. 参考

- [README.md](../README.md) — クイックスタートと概要
- [docs/operations.md](operations.md) — 通常運用ドキュメント
- [CHANGELOG.md](../CHANGELOG.md) — v0.1.0 変更点
- [docs/spike-18-copilot-api-auth.md](spike-18-copilot-api-auth.md) — Copilot API 認証調査
- [tasks.md](../tasks.md) — タスク全体管理（v0.2.0 ロードマップ含む）
