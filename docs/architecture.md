# アーキテクチャ: レビュープラットフォーム MCP ゲートウェイとしての mcp-gateway

このドキュメントは、レビュープラットフォーム内における mcp-gateway の役割、責務境界、および 5 リポジトリ構成の他コンポーネントとの関係を定義します。

## レビュープラットフォーム概要

半自動 PR レビュープラットフォームは、それぞれ独立した責務境界を持つ 5 つのリポジトリで構成されています。

```text
CLI エージェント / デスクトップクライアント
  ↓ 単一の安定した MCP エンドポイント
mcp-gateway
  ├─ /mcp/thread-owl     -> thread-owl MCP サーバー
  ├─ /mcp/review-raven   -> review-raven MCP サーバー
  ├─ /mcp/github         -> github-mcp または互換サーバー
  └─ /mcp/...            -> 追加の MCP サーバー
                ↑
        mcp-docker がコンテナ・ゲートウェイ設定・CLI エージェント設定を管理
```

| # | リポジトリ | 役割 | 責務 |
|---|-----------|------|------|
| 1 | **thread-owl** | レビュアー / subscribe ターゲット | GitHub App 認証、webhook 処理、レビュー候補判定、キュー管理、MCP tools/resources |
| 2 | **mcp-resource-subscriber** | サブスクリプションクライアント / エージェントワークフロー橋渡し | `resources/subscribe` → `notifications/resources/updated` 待機 → `resources/read` → 構造化出力 |
| 3 | **review-raven** | レビューされる側 | Copilot レビュースレッドの取得・返信・解決・再レビュー依頼 |
| 4 | **mcp-gateway** | MCP リバースプロキシ / ルーティングゲートウェイ / 認証境界 | MCP サーバー群のルーティングと認証境界 |
| 5 | **mcp-docker** | MCP コンテナオーケストレーション | コンテナ管理、ゲートウェイルート生成、CLI エージェント設定自動化 |

## mcp-gateway の責務

mcp-gateway は CLI エージェントおよびデスクトップクライアントの単一 HTTP エントリポイントです。以下を担当します。

- 複数の MCP サーバー HTTP エンドポイントを単一ゲートウェイ配下にルーティング
- CLI エージェントおよびデスクトップクライアントから見える MCP エントリポイントを安定させる
- OAuth / 呼び出し元認証 / トークン仲介の境界を提供
- upstream MCP サーバーをプライベート / 内部エンドポイントとして扱えるようにする
- ゲートウェイパスで各レビュープラットフォーム MCP サーバーを識別する
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

## 設計原則

- 多数の個別 MCP サーバーをエージェントに直接登録することを避ける
- クライアント向け URL を mcp-gateway に集約する
- upstream MCP サーバーをプライベート / 内部エンドポイントとして扱う
- ゲートウェイはルーティングと認証に集中し、レビュードメインロジックを持たない
- ゲートウェイはコンテナのライフサイクルを管理しない（それは mcp-docker の責務）
- ゲートウェイ設定は手書き形式と mcp-docker 生成形式の両方をサポートする
