# スパイク調査報告: ルーティング先 MCP サーバーで報告される認証切れの調査 (Issue #105)

## 概要
`mcp-gateway` を経由する複数の MCP サーバーにおいて、認証切れ（401 Unauthorized）が報告されている事象について、永続監査ログ（`auth-audit.jsonl`）および現在のコンテナ構成を調査し、根本原因と責任境界を特定した。

---

## 1. 発生状況の整理
永続監査ログ `auth-audit.jsonl` のレコードより、以下の通り 2 件の顕著な `identity_resolution` 失敗（GitHub API による 401 拒否）が記録されている。

| 発生日時 (UTC) | 対象プロバイダ | 判定結果 | エラークラス | エラー詳細 | HTTP Status | Token Hash |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| `2026-06-14T01:39:34.964Z` | `github` | `failure` | `provider_rejected` | `invalid_token` | 401 | `Vow0Blwa` |
| `2026-06-14T02:41:55.287Z` | `github` | `failure` | `provider_rejected` | `invalid_token` | 401 | `WkKSd6CI` |

### 影響範囲
本障害は、OAuth Provider（GitHub）を使用するすべての認証必須ルート（`github-mcp`, `review-raven`, `thread-owl` など）に共通して発生する。

---

## 2. ログおよび構成の相関分析

### (1) 自動トークンリフレッシュの無効化（根本原因）
`mcp-gateway` のコンテナ起動ログおよび Docker 構成を調査した結果、以下の環境変数が設定されていることが確認された。
- `MCP_GATEWAY_GITHUB_REFRESH_ENABLED=false` (または未指定によるデフォルト `false`)

この設定により、`mcp-gateway` 側に実装されている **GitHub Access Token の自動ローテーション（Phase A / v0.4.0 以降）のパスが完全に無効化（休眠状態）** されていた。
GitHub OAuth の expiring tokens 機能が有効である場合、アクセストークンの寿命は 8 時間である。ローテーションが無効な状態では、8 時間が経過した時点でトークンが失効し、次のリクエスト時の `identity_resolution`（`/user` API コール）で確実に 401 が返される。

### (2) 短時間（45分）でのトークン失効（競合無効化）
2 回目の失敗（`02:41:55.287Z`）は、直前の再認可（ログイン完了：`01:56:16.668Z`）からわずか **45分** で発生している。

監査ログのタイムラインを詳細に確認すると、1 回目の失敗の直後に以下のように**極めて短い時間枠で複数回のログイン処理（認可コードの交換）が連続して発生**していることが判明した。
- `01:55:49.065Z`: 認可コード交換完了（セッションA開始）
- `01:56:05.310Z`: 認可コード交換完了（セッションB開始）
- `01:56:16.668Z`: 認可コード交換完了（セッションC開始）

**分析:**
複数クライアント（または IDE の複数ウィンドウ）がほぼ同時に認証切れを検知し、それぞれが独立して OAuth 認可フローを開始したため、新しい認可トークンが重複して発行された。
GitHub App の仕様において、同一ユーザー・同一インストールに対し新しくリフレッシュトークンが発行されると、古いアクセストークンや古いリフレッシュトークンは即座に、または極めて短い猶予時間（通常 10 分）の後に無効化される。
このため、セッションAやBで取得された古いトークンを使い続けたクライアントが存在した場合、それらのトークンは 8 時間を待たずに 45 分（またはそれ以下）で 401 認証エラーとなる。

---

## 3. 原因分類
本調査で特定された事象は、以下のカテゴリに分類される。

1. **`2. gateway provider refresh / rotation の失敗`**
   - 設定で自動リフレッシュが `false` になっていたため、8 時間経過後のトークン期限切れを自動回復できなかった。
2. **`5. token store / subject index / volume / restart に起因する状態消失、または競合無効化`**
   - 短時間での失効は、複数クライアントからの重複する並行 `/authorize` 処理に伴う GitHub 側トークンの競合無効化が直接的な要因である。

---

## 4. 再現手順
1. `Mcp-Docker` 構成にて `MCP_GATEWAY_GITHUB_REFRESH_ENABLED=false` を設定する。
2. GitHub OAuth を用いてログインし、認証トークンを取得する。
3. トークン取得から 8 時間以上経過させる、あるいは異なるクライアントから複数回連続して OAuth `/authorize` を実行する。
4. その後、ゲートウェイ経由で MCP ツールを実行すると、ゲートウェイは 401 (`invalid_token`) を返し、監査ログに `bearer identity resolution failed` が記録される。

---

## 5. 対応方針

### ① 即時復旧手順
- 影響を受けているユーザーに対し、ブラウザから `http://127.0.0.1:8080/` などのゲートウェイの認証画面にアクセスし、**明示的に再認証（OAuth ログイン）** を実行させる。これにより、有効な新しいアクセストークンとリフレッシュトークンが再取得される。

### ② 恒久対応（Mcp-Docker 側での修正）
- **`Mcp-Docker` の設定変更:**
  `Mcp-Docker/docker-compose.yml` または `.env` において、`MCP_GATEWAY_GITHUB_REFRESH_ENABLED` を `true` に変更する。
  ```yaml
  # Mcp-Docker/docker-compose.yml 内
  - MCP_GATEWAY_GITHUB_REFRESH_ENABLED=${MCP_GATEWAY_GITHUB_REFRESH_ENABLED:-true}
  ```
  この設定を有効化することで、アクセストークンの有効期限が切れる前に `mcp-gateway` が自動的に GitHub OAuth refresh API を呼び出し、トークンをサイレントに更新するようになる。

### ③ 将来の改善課題（mcp-gateway 側）
- **同時認可フローの競合制御:**
  複数クライアントが同時に 401 を検知して同時に OAuth /authorize に突入するのを抑制する、あるいは直近に取得した有効トークンをセッション間で再利用して上書きを避ける仕組みの設計検討。

---

## 6. 責任境界と follow-up Issue
- **`Mcp-Docker` への follow-up 起票:**
  ゲートウェイ側の機能はすでに v0.4.0 で整備完了しているため、コンテナオーケストレーションを担う `Mcp-Docker` 側で `MCP_GATEWAY_GITHUB_REFRESH_ENABLED=true` をデフォルトにする修正が必要。
  - **Issue タイトル案:** `feat: MCP ゲートウェイの GitHub トークン自動ローテーションをデフォルトで有効化する`
  - **AC 案:** `.env.template` および `docker-compose.yml` 内の `MCP_GATEWAY_GITHUB_REFRESH_ENABLED` をデフォルト `true` にし、コンテナを再起動した際に自動リフレッシュが有効になることを確認する。
