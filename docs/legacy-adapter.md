# 過渡期の legacy アダプタ

対応 Issue: [#233](https://github.com/scottlz0310/mcp-gateway/issues/233)。MCP `2026-07-28` 未対応の agy 等から、modern upstream の tools / resources / prompts を利用するための、既定無効の互換層です。

## 設定

```yaml
gateway:
  legacy_adapter_enabled: true
```

環境変数 `GATEWAY_LEGACY_ADAPTER_ENABLED=true` でも有効化できます。優先順位は環境変数 > YAML > `false`。明示的な `false` は YAML の `true` を上書きします。空文字・不正な値は起動エラーになります（Go の `strconv.ParseBool` で解釈）。反映には gateway の再起動が必要です。

設定は全 proxy route に適用されます。有効時の header なし／旧 version の RPC は modern upstream 向けと扱うため、legacy upstream も混在する構成では有効化しないでください。ルート単位の設定はありません。

Mcp-Docker はこの環境変数を gateway コンテナへ渡します。Compose の配線と agy 実接続 E2E は [Mcp-Docker#240](https://github.com/scottlz0310/Mcp-Docker/issues/240) の範囲です。

## 変換と責務境界

`internal/adapter/legacy.NewHandler` を認証・upstream 認可の内側、既存 proxy の直前に登録します。代理 discovery も同じ proxy に渡し、既存の資格情報注入・更新、identity の付与、prefix 除去を再利用します。アダプタ自身は資格情報やセッションを保存しません。

| 入力 | 処理 |
|---|---|
| legacy `initialize` | 同じ JSON-RPC ID で `server/discover` を代理発行。`supportedVersions` と serverInfo を確認し、要求された旧 version の initialize 応答を返す |
| `notifications/initialized` | HTTP 202、空の本文で受理し、upstream へ送らない |
| その他の legacy `notifications/*`（id なし） | MCP `2026-07-28` の Streamable HTTP では client-to-server notification が定義されないため、HTTP 202、空の本文で受理し、upstream へ送らない。キャンセルは legacy client 側の接続終了で表現する |
| 通常の legacy RPC | `Mcp-Protocol-Version`、`Mcp-Method`、必要な `Mcp-Name`、`params._meta` の version / clientCapabilities を補完 |
| modern version header 付き、または `Mcp-Method: server/discover` | 本文を読み取らず既存 proxy へ渡す |
| header なしの `server/discover`、protocol metadata 付き RPC | 判別のため本文を読み取るが、元のバイト列・header をそのまま渡す |
| GET / DELETE、未知 version、不正な JSON、batch | 既存 proxy へ渡す |

対象旧 version は `2024-11-05`、`2025-03-26`、`2025-06-18`、`2025-11-25`。通常 RPC の ID・引数・既存の追加 metadata は保持します。modern の必須 metadata は [公式 schema](https://github.com/modelcontextprotocol/modelcontextprotocol/blob/main/schema/2026-07-28/schema.ts)、標準 header は [Streamable HTTP 仕様](https://github.com/modelcontextprotocol/modelcontextprotocol/blob/main/docs/specification/2026-07-28/basic/transports/streamable-http.mdx) に従います。

旧式の `resources/subscribe`、GET SSE、通知配信、sampling / elicitation 等のサーバーからの callback は変換対象外です。initialize では tools / resources / prompts / completions の存在のみを広告し、subscribe / listChanged / logging / experimental は広告しません。各 RPC の clientCapabilities は空です。

通常 RPC の `Accept` は元の値を保持しつつ、`application/json` と `text/event-stream` が明示されるよう補完します。応答・HTTP error・SSE はそのまま中継します。discovery の JSON / SSE 成功応答のみ initialize に変換し、変換前の ETag 等を除去します。upstream の HTTP / JSON-RPC エラーは透過し、不正な discovery 成功応答は HTTP 502 にします。discovery の失敗時は、本文を記録せず、理由と upstream status のみを `slog.Warn` に記録します。discovery の受信は最大 8 MiB、30 秒。本文判別も最大 8 MiB までで、それを超えるリクエストは変換せず中継します。

## 検証

`go test ./...` でアダプタの変換・無効時の既存透過契約・有効時の modern bypass・SSE・設定優先順位を検証します。実機の agy 接続確認では両 upstream について initialize、tools/list、読み取り専用 tools/call、resources/list と resources/read を確認し、modern client の同時利用も確認します。ローカル単体テストを実機 E2E の代用とはしません。

## 撤去

対象クライアントが `2026-07-28` に正式対応し、アダプタ無効で両 upstream を利用できることが撤去条件です。

1. Mcp-Docker 側で環境変数を `false` にし、再起動後に実接続を検証する。
2. `internal/adapter/legacy`、`cmd/server/main.go` の import・登録・設定解決・起動ログ、`GatewayConfig.LegacyAdapterEnabled` と対応テストを撤去する。
3. YAML / Compose / 環境変数の設定と本ドキュメントへの案内を撤去する。
4. `internal/proxy/mcp_contract_test.go` を含む全テストを実行する。旧 upstream への透過テストは引き続き維持する。

撤去条件の追跡先は #233 / Mcp-Docker#240 です。アダプタの撤去で proxy コアや upstream server の修正は不要です。
