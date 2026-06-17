# ドキュメント

このディレクトリには mcp-gateway の運用リファレンスドキュメントが含まれています。

## ガイド

| ドキュメント | 用途 |
|------------|------|
| [アーキテクチャ](architecture.md) | レビュープラットフォーム概要、責務境界、ルート例、設計原則。 |
| [運用ガイド](operations.md) | 起動・停止手順、ヘルスチェック、構造化ログ、トラブルシュート、デプロイ移行手順。 |
| [設定リファレンス](configuration.md) | 環境変数、`config.yaml`、ルート構文、トークン永続化、リバースプロキシ設定、エンドポイントリファレンス。 |
| [v0.1.0 E2E ランブック](runbook-e2e-v0.1.0.md) | セットアップウィザード・暗号化・ルーティング・トークン永続化・デバイスフローの E2E 受け入れランブック。 |
| [Copilot API Auth Spike](spike-18-copilot-api-auth.md) | Copilot API upstream 認証モデルの調査ノート。 |

## サンプル

| パス | 用途 |
|------|------|
| [`../examples/copilot-review-routing/`](../examples/copilot-review-routing/) | `github-mcp-server` と `copilot-review-mcp` を 1 つのゲートウェイでルーティングする Docker Compose サンプル。 |

## README の構成方針

ルートの [README](../README.md) は意図的に初回起動手順・アーキテクチャ概要・各ドキュメントへのリンクに絞っています。詳細な設定・運用の内容はここに置き、README をスキャンしやすく保ちます。
