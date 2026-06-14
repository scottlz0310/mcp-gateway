# スパイク調査報告: ルーティング先 MCP サーバーで報告される認証切れの調査 (Issue #105)

## 概要
`mcp-gateway` を経由する複数の MCP サーバーにおいて、認証切れ（401 Unauthorized）が報告されている事象について、永続監査ログ（`auth-audit.jsonl`）および現在のコンテナ構成を調査し、根本原因と責任境界を特定した。

---

## 1. 発生状況と対象ルート・オペレーション (AC1)

調査時点の `mcp-gateway` 設定に基づき、認証切れの影響を受けるルート、サーバー、クライアント、およびオペレーションの関係を以下に整理する。

| ルートパス | アップストリームサーバー | 認証方式 (`auth`) | 資格情報インジェクション | 影響度・主なオペレーション |
| :--- | :--- | :--- | :--- | :--- |
| `/mcp/github` | `http://github-mcp:8082` | `oauth` | なし (client token 依存) | **高** (`tools/list`, `tools/call`, `resources/read`) |
| `/mcp/review-raven` | `http://review-raven:8083` | `oauth` | なし (client token 依存) | **高** (`tools/list`, レビュー返信・解決フロー等) |
| `/mcp/thread-owl` | `http://thread-owl:3000` | `oauth` | なし (client token 依存) | **高** (`tools/list`, PR情報の取得・ツール実行) |
| `/mcp/cloudflare` | `https://mcp.cloudflare.com/mcp` | `oauth` | `upstream_bearer_token_env` | **中** (Gateway 側のトークン失効時に影響) |
| `/mcp/playwright` | `http://playwright-mcp:8931` | `none` | なし (認証不要) | **なし** |

### 発生した事象
クライアント（IDE またはエージェントワークフロー）から `mcp-gateway` 経由で各認証必須 MCP サーバーへのリクエスト送信時、ゲートウェイ側で `invalid_token` (HTTP 401) が返され、ツール/リソース実行が失敗する。

---

## 2. ログおよび構成の時系列相関分析 (AC2)

永続監査ログ `auth-audit.jsonl` のレコードより、以下の通り 2 件の `identity_resolution` 失敗（GitHub API による 401 拒否）を抽出した。

| 発生日時 (UTC) | フェーズ | プロバイダ | 結果 | エラークラス | エラー詳細 | HTTP Status | Token Hash |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| `2026-06-14T01:39:34.964Z` | `identity_resolution` | `github` | `failure` | `provider_rejected` | `invalid_token` | 401 | `Vow0Blwa` |
| `2026-06-14T02:41:55.287Z` | `identity_resolution` | `github` | `failure` | `provider_rejected` | `invalid_token` | 401 | `WkKSd6CI` |

### 時系列の相関とシナリオ

#### (1) トークン自動ローテーションの無効化（根本原因）
`mcp-gateway` の現在のコンテナ構成において、以下の設定が確認された。
- `MCP_GATEWAY_GITHUB_REFRESH_ENABLED=false` (または未指定によるデフォルト `false`)

これにより、GitHub Access Token の自動ローテーション（v0.4.0 以降の機能）のパスが完全に無効化（休眠状態）されている。
GitHub OAuth expiring tokens が有効な場合、アクセストークンの寿命は 8 時間である。
- **1回目の失敗時の相関:**
  - `2026-06-13T06:12:17.807Z` に認可コード交換が成功。
  - `2026-06-14T01:39:34.964Z` (**約19.5時間後**) に 401 失敗を検知。
  - 認可から 8 時間以上経過した後にアクセスしたため、アクセストークンが自然失効していた。自動ローテーションが無効であったため回復できなかった。

#### (2) 短時間（45分）でのトークン失効（未確定の仮説）
- **2回目の失敗時の相関:**
  - 1回目の失敗の後、`01:55:49` から `01:56:16` の**約30秒間**に 3 回連続して `token_exchange` 成功（認可コード交換）が記録されている。
  - その後、最後の認可からわずか **45分後** の `02:41:55.287Z` に、Token Hash `WkKSd6CI` に対して 401 失敗が記録された。

**分析と仮説:**
連続した認可コード交換（新しい `/authorize`）のみでは、GitHub 公式の仕様上、既存のアクセストークンが即座に無効化されるわけではない。したがって、45分で失効した直接の原因については、ログの消失もあり以下の「未確定の仮説」として整理する。
- **仮説A (クライアント起因):** クライアント側（または別ウィンドウ）の操作によって明示的にログアウト（トークンの失効 API 呼び出し）が実行された。
- **仮説B (キャッシュ不整合):** 短時間に連続してログインが走った際、ゲートウェイ側のトークンストア/メモリキャッシュの更新タイミングに不整合が生じ、すでに無効な古い中間トークンをクライアントが使い続けた。
- **仮説C (GitHubセキュリティポリシー):** スコープ変更やセキュリティ検知などにより、発行直後の特定のトークンが GitHub 側で明示的に無効化された。

### 相関ログの制約に関する注記
以前のコンテナインスタンスの stdout/stderr ログおよび各 upstream のログは、`08:34` のコンテナ再作成に伴い消失しており、直接的な時系列相関（エラーログの文言一致など）を提示することはできない。しかし、本分析は永続化されている `auth-audit.jsonl` に記録されたタイムスタンプ、エラーコード、ハッシュ値、および現在の設定環境変数との時間的・構造的相関に基づき実施されている。

---

## 3. 原因分類 (AC3, AC4)
全 route に共通する障害か、それとも一部の障害かの判定結果と、原因分類は以下の通りである。

- **判定結果 (AC3):**
  本障害は、ゲートウェイが GitHub OAuth トークンを検証する共通処理 (`identity_resolution`) で発生しているため、**共通の認証プロバイダ (GitHub) を使用するすべての認証必須ルート（`/mcp/github`, `/mcp/review-raven`, `/mcp/thread-owl`）に共通する障害**である。認証不要の `/mcp/playwright` は影響を受けない。
- **原因分類 (AC4):**
  - 1回目の失効: `2. gateway provider refresh / rotation の失敗` (設定が無効化されていたためリフレッシュ自体が行われない)
  - 2回目の失効: `5. token store / subject index / volume / restart に起因する状態消失、または競合無効化` (短時間失効に関する未確定の仮説)

---

## 4. 再現手順 (AC6)

### 8時間経過後の自然失効
1. `Mcp-Docker` 構成にて `MCP_GATEWAY_GITHUB_REFRESH_ENABLED=false` を設定する。
2. GitHub OAuth を用いてログインし、認証トークンを取得する。
3. トークン取得から 8 時間以上経過させる。
4. その後、ゲートウェイ経由で MCP ツールを実行すると、ゲートウェイは 401 (`invalid_token`) を返し、監査ログに `bearer identity resolution failed` が記録される。

### 45分失効（仮説Bの再現検証手順案）
1. 短時間（数十秒間）に連続して異なるクライアント/ブラウザセッションから同一のアカウントで OAuth 認可フローを実行する。
2. ゲートウェイのインメモリキャッシュと DB 側のストア間で、特定のクライアントが古いアクセストークンを保持したままリクエストを送信し、無効化を誘発できるか確認する（※再現性は環境やタイミングに依存するため未確定）。

---

## 5. 対応方針と即時復旧・恒久対応の分離 (AC7)

### ① 即時復旧手順
- 影響を受けているユーザーに対し、ブラウザから `http://127.0.0.1:8080/` などのゲートウェイの認証画面にアクセスし、**明示的に再認証（OAuth ログイン）** を実行させる。これにより、有効な新しいアクセストークンとリフレッシュトークンが再取得される。

### ② 恒久対応（Mcp-Docker 側での修正）
- **`Mcp-Docker` の設定変更:**
  `Mcp-Docker/docker-compose.yml` または `.env` において、`MCP_GATEWAY_GITHUB_REFRESH_ENABLED` を `true` に変更する。
  ```yaml
  # Mcp-Docker/docker-compose.yml
  - MCP_GATEWAY_GITHUB_REFRESH_ENABLED=${MCP_GATEWAY_GITHUB_REFRESH_ENABLED:-true}
  ```
  この設定を有効化することで、アクセストークンの有効期限が切れる前に `mcp-gateway` が自動的に GitHub OAuth refresh API を呼び出し、トークンをサイレントに更新するようになる。

---

## 6. 責任境界と follow-up Issue 起票 (AC8)

本問題の根本原因は `Mcp-Docker` のコンテナ起動パラメータの設定不備にある。そのため、`Mcp-Docker` リポジトリへ以下の通り Issue を実際に起票した。

- **起票先リポジトリ:** `scottlz0310/Mcp-Docker`
- **起票済み Issue:** [scottlz0310/Mcp-Docker#178](https://github.com/scottlz0310/Mcp-Docker/issues/178)
- **Issue タイトル:** `feat: MCP ゲートウェイの GitHub トークン自動ローテーションをデフォルトで有効化する`
- **内容:**
  - `docker-compose.yml` 内の `MCP_GATEWAY_GITHUB_REFRESH_ENABLED` 環境変数のデフォルト値を `true` に設定する。
  - `.env.template` に `MCP_GATEWAY_GITHUB_REFRESH_ENABLED=true` を明記し、自動ローテーション機能の利用を推奨するドキュメントを追加する。
  - 動作検証として、コンテナ起動ログに `"github_refresh_enabled":true` が出力されることを確認する。
