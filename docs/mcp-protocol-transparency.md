# MCP プロトコル透過契約

mcp-gateway は MCP のリバースプロキシかつ認証境界であり、**MCP サーバーではありません**。この文書は、その責務境界のうち「プロトコルネゴシエーションに対して何をしてはならないか」を契約として定義し、契約を固定しているテストと、横断 E2E の受け入れ条件を示します。

- 対応 issue: [#216](https://github.com/scottlz0310/mcp-gateway/issues/216)
- 横断 tracker: [thread-owl#165](https://github.com/scottlz0310/thread-owl/issues/165)
- 契約テスト: [`internal/proxy/mcp_contract_test.go`](../internal/proxy/mcp_contract_test.go)

## 背景

MCP `2026-07-28` は、それ以前のプロトコルから接続の確立方法そのものが変わりました。

| 〜`2025-11-25` | `2026-07-28` |
|---|---|
| `initialize` 先行 | `server/discover` 先行（discovery-first） |
| `Mcp-Session-Id` による protocol-level session | **session なし**（stateless） |
| standalone GET SSE endpoint | `subscriptions/listen` の POST レスポンスがそのまま long-lived SSE stream |
| `resources/subscribe` / `resources/unsubscribe` | `subscriptions/listen` の `notifications.resourceSubscriptions` に統合 |

いずれの変更も、**gateway から見れば「ヘッダー・JSON-RPC ボディ・HTTP ステータス・ストリームの寿命」に現れます**。gateway がこれらのどれか一つでも生成・吸収・書き換えを行うと、client と upstream server のネゴシエーションは gateway の内部都合で壊れます。したがって gateway 側の要件は「プロトコルに追従する」ことではなく、**プロトコルに対して透明であり続けること**です。

## 契約

### 1. gateway は MCP サーバーの応答を生成しない

- `server/discover` に対して gateway が成功応答・フォールバック応答・capability の合成を行ってはならない
- upstream の capability を集約・書き換え・フィルタしてはならない
- `initialize` / `subscriptions/listen` など、他の MCP メソッドについても同様

ネゴシエーションの結果は常に upstream server が決めます。

### 2. ネゴシエーションに関わる要素を書き換えない

| 対象 | 要件 |
|---|---|
| `MCP-Protocol-Version` ヘッダー | request / response の双方向でそのまま透過する。SDK は本ヘッダーと `_meta.protocolVersion` の不一致を `CodeHeaderMismatch` で拒否するため、書き換えは接続を壊す |
| JSON-RPC リクエスト / レスポンスボディ | バイト列を変更しない。JSON-RPC ID を保持する |
| HTTP ステータスコード | upstream の値をそのまま返す。ネゴシエーション失敗（400）や `405 Method Not Allowed` を別のステータスに正規化しない |
| `Mcp-Session-Id` | **mint も echo もしない**。client / upstream が送れば透過し、gateway が独自に発行・要求することはない |

### 3. stateless を前提にする

`2026-07-28` に protocol-level session は存在しません。gateway は session affinity も session storage も要求しません。同一 client からの連続したリクエストが同じ upstream プロセスに到達することを前提とした実装を持ち込まないでください。

`Mcp-Session-Id` の透過は、旧プロトコルの upstream をルーティングし続けるための回帰要件として残します。gateway 側で session を解釈することはありません。

### 4. long-lived SSE stream をバッファリングしない

`subscriptions/listen` のレスポンスは、購読が続く限り開いたままになります。

- レスポンスをチャンク単位でそのまま流す（`httputil.ReverseProxy` は `text/event-stream` を検知して即時 flush する）
- keep-alive の SSE コメント行（`:` で始まる行）をフィルタ・結合・整形しない
- `X-Accel-Buffering` は upstream の値を優先し、upstream が付けていない SSE レスポンスにのみ gateway が `no` を補う（gateway の前段に nginx 等が入る配備でストリームが滞留しないようにするため）

### 5. 認証エラーとネゴシエーションエラーを混同しない

- gateway が発行する認証エラーは `401` + `WWW-Authenticate`（RFC 6750）であり、**upstream に到達しない**
- upstream が返すネゴシエーションエラー（`400` の JSON-RPC error 等）はそのまま client に返す。`WWW-Authenticate` を付けない、トークンキャッシュを破棄しない
- upstream の `401` のみを認証シグナルとして扱う

## gateway が明示的に適用する変更

透過が原則ですが、認証境界として以下だけは意図的に手を入れます。ここに列挙されていない変更を追加する場合は、本契約とテストを併せて更新してください。

| 変更 | 理由 |
|---|---|
| client の `Authorization` を除去し、ルート設定に応じた upstream 資格情報を注入 | 資格情報のなりすまし防止と upstream 認証 |
| `X-Authenticated-User`（および移行期間の `X-GitHub-Login`）を付与 | 検証済み identity の受け渡し。client 供給値は必ず除去してから付与する |
| `X-Forwarded-*` / `Forwarded` / `X-Real-Ip` を除去 | client による偽装防止 |
| ルート prefix の除去 | upstream のパス空間へのマッピング |
| SSE レスポンスへの `X-Accel-Buffering: no` 補完 | 前段プロキシによるストリーム滞留の防止（上記 4） |

## 契約テスト

`internal/proxy/mcp_contract_test.go` が上記を固定します。

| テスト | 固定する契約 |
|---|---|
| `TestMCPNegotiationHeadersPassThrough` | `MCP-Protocol-Version` / `Mcp-Session-Id` の双方向透過（modern / legacy 両方） |
| `TestGatewayDoesNotMintSession` | session を発行しない・要求しない（stateless） |
| `TestServerDiscoverPassThrough` | `server/discover` のボディ・JSON-RPC ID・ステータスの保持、GET / DELETE の `405` 透過 |
| `TestProxyStreamsSSEWithoutBuffering` | long-lived SSE stream の逐次転送と keep-alive コメント行のバイト単位保持 |
| `TestSSEAccelBufferingHint` | `X-Accel-Buffering` の優先順位（upstream 優先・SSE のみ補完） |
| `TestNegotiationErrorIsNotTreatedAsAuthError` | ネゴシエーション失敗を認証エラーとして扱わない |
| `TestAuthErrorNeverReachesUpstream` | 認証エラーが upstream に到達しない |

`TestProxyStreamsSSEWithoutBuffering` は、upstream が「client が最初のチャンクを受け取るまで次を書かない」構成になっています。gateway がレスポンスを溜め込むとレスポンスヘッダー自体が返らず、リクエストのデッドライン超過として失敗します。

## 横断 E2E の受け入れ条件

実行は [Mcp-Docker#230](https://github.com/scottlz0310/Mcp-Docker/issues/230) が担当します。gateway 側が満たすべき条件をここで定義します。

### 共通条件

1. client → gateway → upstream の経路で `server/discover` が成功し、**`2026-07-28` がネゴシエートされる**こと（`2025-11-25` へのフォールバックが起きないこと）
2. gateway 経由・直結の双方で、`server/discover` のレスポンスボディが一致すること（gateway が capability を加工していないことの確認）
3. gateway のレスポンスに `Mcp-Session-Id` が現れないこと
4. gateway への `GET` / `DELETE` が upstream の `405` をそのまま返すこと

### thread-owl を upstream とする条件

5. `subscriptions/listen` の POST が SSE stream として開き、**最初のメッセージが `notifications/subscriptions/acknowledged`** であること
6. レビューキュー更新をトリガーしてから `notifications/resources/updated` が client に届くこと。gateway 直結時と比べて有意な遅延がないこと
7. 通知の `_meta` に載る `io.modelcontextprotocol/subscriptionId` が listen リクエストの JSON-RPC ID と一致すること
8. **アイドル状態で keep-alive コメント行が client に到達し続け**、gateway / 前段プロキシの idle timeout で切断されないこと（[#204](https://github.com/scottlz0310/mcp-gateway/issues/204) の再発検知を兼ねる）
9. stream を client 側から閉じたとき、upstream が購読解除として扱えること（gateway が close を握り潰さないこと）

### review-raven を upstream とする条件

10. tool 呼び出しが `2026-07-28` 上で成功すること
11. upstream が stateless で動作している状態で、連続する複数リクエストが session なしで成立すること
12. upstream の `401` が gateway の認証再試行を正しく誘発し、upstream のネゴシエーションエラー（`400`）は誘発しないこと

### squirrel-notifier を client とする条件

13. 60 秒再購読ループを撤去した subscriber が、long-lived stream 1 本でトースト通知を受け続けられること

## 関連

- [アーキテクチャ](architecture.md) — 責務境界の全体像
- [運用ガイド](operations.md) — `Mcp-Session-Id` 関連のトラブルシュート（旧プロトコル向け）
