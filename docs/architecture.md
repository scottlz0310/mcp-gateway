# アーキテクチャ: レビュープラットフォーム MCP ゲートウェイとしての mcp-gateway

このドキュメントは、レビュープラットフォーム内における mcp-gateway の役割、責務境界、および 6 リポジトリ構成の他コンポーネントとの関係を定義します。

## レビュープラットフォーム概要

半自動 PR レビュープラットフォームは、それぞれ独立した責務境界を持つ 6 つのリポジトリで構成されています。

```text
CLI エージェント / デスクトップクライアント
  ↑ (トースト通知からのユーザー操作により起動)
squirrel-notifier (デスクトップ常駐 / AI エージェントランチャー)
  ↓ config/token
mcp-gateway (routing & auth boundary)
  ↓ routes
thread-owl / review-raven / github-mcp / 追加 MCP サーバー
          ↑
  mcp-docker が container / gateway route / agent config を管理
```

| # | リポジトリ | 立場 | 責務 |
|---|-----------|------|------|
| 1 | **thread-owl** | review する側 / subscribe される側 | GitHub App 認証・webhook 受信・review candidate 判定・queue 管理・MCP tools/resources 提供 |
| 2 | **mcp-resource-subscriber** | subscribe する側 / agent workflow bridge | `resources/subscribe` → `notifications/resources/updated` 待機 → `resources/read` → 構造化出力 |
| 3 | **review-raven** | review を受けて直す側 | Copilot レビュースレッド取得・返信・resolve・再レビュー依頼 |
| 4 | **mcp-gateway** | MCP reverse proxy / routing gateway / auth boundary | MCP server 群への routing と認証境界 |
| 5 | **mcp-docker** | MCP container orchestration | container 管理・gateway route 生成・CLI agent 設定自動化 |
| 6 | **squirrel-notifier** | 通知受信 / AI エージェントランチャー | mcp-gateway 経由で MCP resource 更新（レビュー更新イベント等）を監視してトースト通知。トースト通知からローカルの AI エージェントを skill 指定で起動 |

## mcp-gateway の責務

mcp-gateway は CLI エージェントおよびデスクトップクライアントの単一 HTTP エントリポイントです。以下を担当します。

- 複数の MCP サーバー HTTP エンドポイントを単一ゲートウェイ配下にルーティング
- CLI エージェントおよびデスクトップクライアントから見える MCP エントリポイントを安定させる
- OAuth / 呼び出し元認証 / トークン仲介の境界を提供
- upstream MCP サーバーをプライベート / 内部エンドポイントとして扱えるようにする
- ゲートウェイパスで各レビュープラットフォーム MCP サーバーを識別する
- upstream OAuth 委任（`authorization_code` / `client_credentials`）によって upstream AS との token lifecycle を管理する
- ルート設定・ヘルス・whoami・トークンソース等の運用 API を提供（一部将来実装）

## mcp-gateway が担当しないこと

以下の責務は他コンポーネントに属し、mcp-gateway に実装してはなりません。

| 責務 | オーナー |
|------|---------|
| レビュー候補判定 | thread-owl |
| webhook 処理 | thread-owl |
| レビューキュー管理 | thread-owl |
| PR レビューコンテンツ生成 | review-raven |
| レビュースレッド返信 / 解決 | review-raven |
| 長命 resource subscription 待機 CLI | mcp-resource-subscriber |
| MCP サーバーコンテナのライフサイクル管理 | mcp-docker |
| CLI エージェント設定ファイル生成 | mcp-docker |
| トースト通知・AI エージェント起動 | squirrel-notifier |

## ルート例

```text
/mcp/thread-owl     -> thread-owl MCP サーバー
/mcp/review-raven   -> review-raven MCP サーバー
/mcp/github         -> github-mcp または互換サーバー
/mcp/other          -> 追加の MCP サーバー
```

upstream ルートは環境変数で設定します。

```yaml
environment:
  ROUTE_THREAD_OWL:   /mcp/thread-owl|http://thread-owl:8081
  ROUTE_REVIEW_RAVEN: /mcp/review-raven|http://review-raven:8083
  ROUTE_GITHUB:       /mcp/github|http://github-mcp:8082
```

upstream AS が独自 OAuth を要求する場合は `upstream_oauth` を追加します。

```yaml
environment:
  ROUTE_CLOUDFLARE: /mcp/cf|https://cf-mcp.example.com/mcp|upstream_oauth=auto|upstream_oauth_scope=read
```

## mcp-docker との関係

mcp-docker がコンテナのライフサイクルを管理し、ゲートウェイ設定を生成します。mcp-gateway は生成された設定を読み込み、ランタイムのルーティングと認証を処理します。

```text
mcp-docker
  ├─ コンテナの起動・管理
  ├─ ゲートウェイ設定の生成・更新
  └─ CLI エージェント設定の生成

mcp-gateway
  ├─ 生成された設定の読み込み
  ├─ /mcp/* を upstream MCP サーバーへルーティング
  └─ 呼び出し元認証 / トークン仲介の処理
```

ゲートウェイ設定は mcp-docker が生成することも手書きで記述することも可能です。両方をサポートしていますが、mcp-docker による生成が推奨の運用パスです。

## squirrel-notifier との関係

squirrel-notifier はデスクトップ常駐プロセスとして、mcp-gateway を経由して MCP resource 更新イベントを監視します。mcp-gateway は squirrel-notifier に対して通常の MCP クライアントと同様の認証境界を提供します。squirrel-notifier は mcp-gateway の内部実装に依存せず、公開エンドポイントのみを使用します。

```text
squirrel-notifier
  ├─ mcp-resource-subscriber を子プロセスとして呼び出し
  ├─ mcp-gateway 経由で thread-owl の resource を subscribe
  ├─ 更新イベントを受信してトースト通知を表示
  └─ ユーザー操作に応じてローカル AI エージェントを skill 指定で起動
```

## 設計原則

- 多数の個別 MCP サーバーをエージェントに直接登録することを避ける
- クライアント向け URL を mcp-gateway に集約する
- upstream MCP サーバーをプライベート / 内部エンドポイントとして扱う
- ゲートウェイはルーティングと認証に集中し、レビュードメインロジックを持たない
- ゲートウェイはコンテナのライフサイクルを管理しない（それは mcp-docker の責務）
- ゲートウェイ設定は手書き形式と mcp-docker 生成形式の両方をサポートする
- 各コンポーネントは独立して開発・更新・置き換えできる責務境界を持つ
