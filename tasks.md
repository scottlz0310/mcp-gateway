# Tasks

`mcp-gateway` の現在の未実装 GitHub Issue を、優先度と実装依存に沿って管理する。

完了済みの履歴は archive に移し、このファイルには原則として open issue と次に着手すべき順序だけを残す。

- v0.1.0 から v0.3.0 まで: [`docs/tasks-archive-v0.3.0.md`](docs/tasks-archive-v0.3.0.md)
- v0.4.0 から v0.6.0 まで: [`docs/tasks-archive-v0.6.0.md`](docs/tasks-archive-v0.6.0.md)
- 公開リリース単位の履歴: [`CHANGELOG.md`](CHANGELOG.md) / [`CHANGELOG.ja.md`](CHANGELOG.ja.md)

## 凡例

- `[ ]` 未着手
- `[~]` 設計済み / 管理中
- `[x]` 完了
- `[-]` 保留 / 別 issue へ移管

---

## 現在の判断基準

- 対象: 2026-06-21 時点の open issue
- `#126` は設計決定 issue。Phase 1 (v0.6.0) + Phase 2 (v0.7.0) で実装完了。2026-06-21 にクローズ済み。
- `#84` は upstream OAuth delegation の親 issue。実装 chain（#113〜#118, #166, #171）+ 関連修正（#162, #175, #177, #179）すべて完了。2026-06-21 にクローズ済み。
- `#65` は Renovate Dependency Dashboard であり、通常の実装ロードマップには含めない。open 維持。

---

## 推奨実装順（v0.7.0 時点でのすべての実装が完了）

| 優先 | Issue | 状態 | 依存 | 次のアクション |
|---|---|---|---|---|
| P0 | [#122](https://github.com/scottlz0310/mcp-gateway/issues/122) OIDC Discovery metadata 補完 | [x] | なし | 完了（v0.7.0） |
| P0 | [#123](https://github.com/scottlz0310/mcp-gateway/issues/123) OIDC `nonce` claim 対応 | [x] | なし | 完了（v0.7.0） |
| P1 | [#125](https://github.com/scottlz0310/mcp-gateway/issues/125) RFC 8252 opaque-form redirect URI | [x] | なし | 完了（v0.7.0） |
| P1 | [#6](https://github.com/scottlz0310/mcp-gateway/issues/6) gateway OIDC Provider 完成 / agy 完走 | [x] | `#122` / `#123` / `#125` | 完了（v0.6.0） |
| P2 | [#113](https://github.com/scottlz0310/mcp-gateway/issues/113) upstream OAuth route option | [x] | なし | 完了（v0.7.0） |
| P2 | [#114](https://github.com/scottlz0310/mcp-gateway/issues/114) upstream OAuth discovery + DCR | [x] | `#113` | 完了（v0.7.0） |
| P2 | [#115](https://github.com/scottlz0310/mcp-gateway/issues/115) upstream token store | [x] | `#114` | 完了（v0.7.0） |
| P2 | [#116](https://github.com/scottlz0310/mcp-gateway/issues/116) upstream OAuth authorization flow | [x] | `#114` / `#115` | 完了（v0.7.0） |
| P2 | [#117](https://github.com/scottlz0310/mcp-gateway/issues/117) proxy token injection | [x] | `#113`-`#116` | 完了（v0.7.0） |
| P2 | [#118](https://github.com/scottlz0310/mcp-gateway/issues/118) upstream token refresh | [x] | `#117` | 完了（v0.7.0） |
| P2 | [#162](https://github.com/scottlz0310/mcp-gateway/issues/162) builtin provider identity resolution 修正 | [x] | なし | 完了（v0.7.0） |
| P2 | [#166](https://github.com/scottlz0310/mcp-gateway/issues/166) upstream OAuth Manager 統合 + client_credentials フロー | [x] | `#113`-`#118` | 完了（v0.7.0） |
| P2 | [#171](https://github.com/scottlz0310/mcp-gateway/issues/171) LookupForRefresh — 期限切れトークンの refresh 対応 | [x] | `#118` | 完了（v0.7.0） |
| P2 | [#175](https://github.com/scottlz0310/mcp-gateway/issues/175) buildResourceAudienceMap URL キー + gateway-wide PRM 修正 | [x] | なし | 完了（v0.7.0） |
| P2 | [#177](https://github.com/scottlz0310/mcp-gateway/issues/177) DCR 登録ごとに一意の client_id を発行（RFC 7591） | [x] | `#114` | 完了（v0.7.0） |
| P2 | [#179](https://github.com/scottlz0310/mcp-gateway/issues/179) upstream OAuth 302 → 200 JSON-RPC error | [x] | `#116` | 完了（v0.7.0） |

---

## Phase 1: OIDC Authorization Server の仕様補完

設計アンカー: [#126](https://github.com/scottlz0310/mcp-gateway/issues/126)

`#127` GitHub social login layer、`#128` refresh token rotation / reuse detection、`#129` audience 分離、`#130` gateway-native Device Authorization Grant は v0.6.0 で完了済み。残件はすべて完了済み。

### [#122](https://github.com/scottlz0310/mcp-gateway/issues/122) OIDC Discovery に `code_challenge_methods_supported` を追加

- [x] `OIDCDiscovery` に `code_challenge_methods_supported: ["S256"]` を追加
- [x] `grant_types_supported` に `authorization_code` / `refresh_token` / `urn:ietf:params:oauth:grant-type:device_code` を追加
- [x] `registration_endpoint` と `device_authorization_endpoint` を追加
- [x] `internal/auth/handler_test.go` に OIDC Discovery の regression test を追加

### [#123](https://github.com/scottlz0310/mcp-gateway/issues/123) OIDC Provider の `nonce` claim 対応

- [x] `/authorize` で `nonce` パラメータを読み取り session に保存
- [x] authorization code exchange の結果に `nonce` を含める
- [x] `writeTokenResponse` / `generateIDToken` まで `nonce` を伝播
- [x] `nonce` が空でない場合のみ `id_token` payload に含める
- [x] OIDC Core §3.1.3.7 の期待に沿うテストを追加

### [#125](https://github.com/scottlz0310/mcp-gateway/issues/125) RFC 8252 opaque-form カスタムスキーム URI

- [x] `http` / `https` は従来通り host 必須で検証
- [x] custom scheme は `Host != ""` または `Opaque != ""` のどちらかを許可
- [x] fragment 付き redirect URI は引き続き拒否
- [x] `com.example.app:/oauth2redirect/provider` の許可テストを追加
- [x] host も opaque もない custom scheme を拒否するテストを追加

### [#6](https://github.com/scottlz0310/mcp-gateway/issues/6) gateway OIDC Provider / agy 認証フロー完走

- [x] agy から Authorization Code + PKCE フローが完走することを確認
- [x] gateway が自身の `access_token` / `id_token` を発行し、GitHub access token を client に渡さないことを確認
- [x] 既存の `upstream_bearer_token_env` と upstream OAuth delegation 設計に影響がないことを確認

---

## Phase 2: upstream OAuth delegation

親 issue: [#84](https://github.com/scottlz0310/mcp-gateway/issues/84)

Cloudflare MCP など、upstream が独自 OAuth サーバーを持つケースに対応する。`upstream_bearer_token_env` による静的 token injection とは別の機能として、ユーザーごとの upstream OAuth フローを gateway が仲介する。

全 issue 完了済み（#113〜#118, #162, #166, #171, #175, #177, #179）。v0.7.0 リリース準備済み（PR #181）。

### [#113](https://github.com/scottlz0310/mcp-gateway/issues/113) route option parse / validation

- [x] `internal/router.Route` に `UpstreamOAuth` / `UpstreamOAuthScope` を追加
- [x] `ROUTE_*` の `upstream_oauth=auto|https://...` を parse
- [x] `upstream_oauth_scope` を parse し、空白のみは拒否
- [x] `upstream_oauth` と `upstream_bearer_token_env` の同時指定を fail-closed
- [x] `config.yaml` route でも同じ validation を適用

### [#114](https://github.com/scottlz0310/mcp-gateway/issues/114) discovery / Dynamic Client Registration

- [x] `upstream_oauth=auto` で RFC 9728 PRM から authorization server を発見
- [x] 明示 issuer URL では RFC 8414 metadata を直接取得
- [x] discovery 結果を route 単位で遅延取得・キャッシュ
- [x] DCR で `client_id` / `client_secret` を取得
- [x] `upstream_clients.json` を 0600 + atomic write で永続化

### [#115](https://github.com/scottlz0310/mcp-gateway/issues/115) upstream user token store

- [x] `UpstreamTokenStore` interface を追加
- [x] in-memory 実装と JSON file-backed 実装を追加
- [x] on-disk key を `sha256(subject + "\x00" + routeName)` にして raw identity を本文に保存しない
- [x] `ExpiresAt` に基づく lookup / sweep を実装
- [x] `TokenStorePath` と同一ディレクトリに `upstream_tokens.json` を置く

### [#116](https://github.com/scottlz0310/mcp-gateway/issues/116) upstream authorization flow

- [x] upstream OAuth state store を TTL 付き in-memory で実装
- [x] PKCE `code_verifier` / `code_challenge` を生成
- [x] `/upstream/callback/{route-name}` を追加
- [x] callback では state store から subject を復元し、middleware context に依存しない
- [x] token endpoint から取得した token を `UpstreamTokenStore` に保存

### [#117](https://github.com/scottlz0310/mcp-gateway/issues/117) proxy integration

- [x] `upstream_oauth` route では user-specific upstream token を `Authorization: Bearer` として注入
- [x] token がない場合は upstream OAuth 認可フローへ誘導
- [x] upstream 401 では該当 upstream token を削除し、gateway OAuth cache invalidation と混在させない
- [x] `upstream_bearer_token_env` と既存 client token path の regression test を追加

### [#118](https://github.com/scottlz0310/mcp-gateway/issues/118) proactive refresh / 401 retry

- [x] `ExpiresAt` が近い upstream token を proxy 注入前に refresh
- [x] `ExpiresAt == zero` は期限不明として proactive refresh しない
- [x] temporary refresh failure では既存 token を継続利用
- [x] permanent refresh failure では token を削除して再認証へ誘導
- [x] upstream 401 後に refresh / retry する
- [x] 同一 subject x route の refresh を singleflight で排他

### [#166](https://github.com/scottlz0310/mcp-gateway/issues/166) upstream OAuth Manager 統合 + client_credentials フロー

- [x] `upstream_oauth_grant` ルートオプションで `authorization_code` / `client_credentials` を選択可能に
- [x] `client_credentials` フロー実装（バックグラウンドトークン取得）
- [x] `ClientRecord.Grant` / `UpstreamTokenRecord.Grant` で grant-aware キャッシュ
- [x] grant 変更時に旧 DCR 登録・旧トークンを自動再取得

### [#171](https://github.com/scottlz0310/mcp-gateway/issues/171) LookupForRefresh — 期限切れトークンの refresh 対応

- [x] `UpstreamTokenStore` インターフェースに `LookupForRefresh` を追加
- [x] `memUpstreamTokenStore` / `fileUpstreamTokenStore` に実装を追加
- [x] `RefreshAfter401` で `LookupForRefresh` を使用して期限切れ access token でも refresh_token を取得可能に
- [x] 期限切れ access token + 有効 refresh_token のシナリオテストを追加

---

## 運用枠

### [#65](https://github.com/scottlz0310/mcp-gateway/issues/65) Dependency Dashboard

- [~] Renovate 管理 issue。open のまま維持する
- [ ] Renovate branch が発生した場合のみ、通常の依存更新 PR として個別に扱う
