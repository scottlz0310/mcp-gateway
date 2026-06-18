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

- 対象: 2026-06-18 時点の open issue
- `#126` は設計決定 issue であり、直接の実装単位ではない。実装は `#122` / `#123` / `#125` / `#6` へ寄せる。
- `#84` は upstream OAuth delegation の親 issue。実装は `#113` から `#118` の直列 chain で進める。
- `#65` は Renovate Dependency Dashboard であり、通常の実装ロードマップには含めない。

---

## 推奨実装順

| 優先 | Issue | 状態 | 依存 | 次のアクション |
|---|---|---|---|---|
| P0 | [#122](https://github.com/scottlz0310/mcp-gateway/issues/122) OIDC Discovery metadata 補完 | [x] | なし | `/.well-known/openid-configuration` に PKCE / grant / registration / device metadata を追加 |
| P0 | [#123](https://github.com/scottlz0310/mcp-gateway/issues/123) OIDC `nonce` claim 対応 | [ ] | なし | `nonce` を authorize session から `id_token` まで伝播 |
| P1 | [#125](https://github.com/scottlz0310/mcp-gateway/issues/125) RFC 8252 opaque-form redirect URI | [ ] | なし | custom scheme の `Opaque` 形式を許可し、HTTP(S) とは別に validation |
| P1 | [#6](https://github.com/scottlz0310/mcp-gateway/issues/6) gateway OIDC Provider 完成 / agy 完走 | [ ] | `#122` / `#123` / `#125` 推奨先行、`#127` / `#128` / `#130` 完了済み | #126 前提の AC で agy / device flow / gateway-issued JWT を E2E 確認 |
| P2 | [#113](https://github.com/scottlz0310/mcp-gateway/issues/113) upstream OAuth route option | [ ] | なし | `upstream_oauth` / `upstream_oauth_scope` の parse / validation を追加 |
| P2 | [#114](https://github.com/scottlz0310/mcp-gateway/issues/114) upstream OAuth discovery + DCR | [ ] | `#113` | RFC 9728 / RFC 8414 discovery と DCR client store を実装 |
| P2 | [#115](https://github.com/scottlz0310/mcp-gateway/issues/115) upstream token store | [ ] | `#114` | `(subject, route_name)` keyed token store を追加 |
| P2 | [#116](https://github.com/scottlz0310/mcp-gateway/issues/116) upstream OAuth authorization flow | [ ] | `#114` / `#115` | PKCE / state / `/upstream/callback/{route-name}` を実装 |
| P2 | [#117](https://github.com/scottlz0310/mcp-gateway/issues/117) proxy token injection | [ ] | `#113`-`#116` | proxy に upstream token injection と再認証誘導を統合 |
| P2 | [#118](https://github.com/scottlz0310/mcp-gateway/issues/118) upstream token refresh | [ ] | `#117` | proactive refresh と 401 後 refresh/retry を追加 |

---

## Phase 1: OIDC Authorization Server の仕様補完

設計アンカー: [#126](https://github.com/scottlz0310/mcp-gateway/issues/126)

`#127` GitHub social login layer、`#128` refresh token rotation / reuse detection、`#129` audience 分離、`#130` gateway-native Device Authorization Grant は v0.6.0 で完了済み。残件は OIDC metadata / nonce / native redirect URI の仕様補完と、agy を含む E2E 完走確認。

### [#122](https://github.com/scottlz0310/mcp-gateway/issues/122) OIDC Discovery に `code_challenge_methods_supported` を追加

- [x] `OIDCDiscovery` に `code_challenge_methods_supported: ["S256"]` を追加
- [x] `grant_types_supported` に `authorization_code` / `refresh_token` / `urn:ietf:params:oauth:grant-type:device_code` を追加
- [x] `registration_endpoint` と `device_authorization_endpoint` を追加
- [x] `internal/auth/handler_test.go` に OIDC Discovery の regression test を追加

### [#123](https://github.com/scottlz0310/mcp-gateway/issues/123) OIDC Provider の `nonce` claim 対応

- [ ] `/authorize` で `nonce` パラメータを読み取り session に保存
- [ ] authorization code exchange の結果に `nonce` を含める
- [ ] `writeTokenResponse` / `generateIDToken` まで `nonce` を伝播
- [ ] `nonce` が空でない場合のみ `id_token` payload に含める
- [ ] OIDC Core §3.1.3.7 の期待に沿うテストを追加

### [#125](https://github.com/scottlz0310/mcp-gateway/issues/125) RFC 8252 opaque-form カスタムスキーム URI

- [ ] `http` / `https` は従来通り host 必須で検証
- [ ] custom scheme は `Host != ""` または `Opaque != ""` のどちらかを許可
- [ ] fragment 付き redirect URI は引き続き拒否
- [ ] `com.example.app:/oauth2redirect/provider` の許可テストを追加
- [ ] host も opaque もない custom scheme を拒否するテストを追加

### [#6](https://github.com/scottlz0310/mcp-gateway/issues/6) gateway OIDC Provider / agy 認証フロー完走

- [ ] 実装着手前に #126 の設計決定を前提として受け入れ基準を再確認
- [ ] agy から Authorization Code + PKCE フローが完走することを確認
- [ ] gateway が自身の `access_token` / `id_token` を発行し、GitHub access token を client に渡さないことを確認
- [ ] Claude CLI / Copilot CLI が device flow または互換モードで認証できることを確認
- [ ] 既存の `upstream_bearer_token_env` と upstream OAuth delegation 設計に影響がないことを確認

---

## Phase 2: upstream OAuth delegation

親 issue: [#84](https://github.com/scottlz0310/mcp-gateway/issues/84)

Cloudflare MCP など、upstream が独自 OAuth サーバーを持つケースに対応する。`upstream_bearer_token_env` による静的 token injection とは別の機能として、ユーザーごとの upstream OAuth フローを gateway が仲介する。

### [#113](https://github.com/scottlz0310/mcp-gateway/issues/113) route option parse / validation

- [ ] `internal/router.Route` に `UpstreamOAuth` / `UpstreamOAuthScope` を追加
- [ ] `ROUTE_*` の `upstream_oauth=auto|https://...` を parse
- [ ] `upstream_oauth_scope` を parse し、空白のみは拒否
- [ ] `upstream_oauth` と `upstream_bearer_token_env` の同時指定を fail-closed
- [ ] `config.yaml` route でも同じ validation を適用

### [#114](https://github.com/scottlz0310/mcp-gateway/issues/114) discovery / Dynamic Client Registration

- [ ] `upstream_oauth=auto` で RFC 9728 PRM から authorization server を発見
- [ ] 明示 issuer URL では RFC 8414 metadata を直接取得
- [ ] discovery 結果を route 単位で遅延取得・キャッシュ
- [ ] DCR で `client_id` / `client_secret` を取得
- [ ] `upstream_clients.json` を 0600 + atomic write で永続化

### [#115](https://github.com/scottlz0310/mcp-gateway/issues/115) upstream user token store

- [ ] `UpstreamTokenStore` interface を追加
- [ ] in-memory 実装と JSON file-backed 実装を追加
- [ ] on-disk key を `sha256(subject + "\x00" + routeName)` にして raw identity を本文に保存しない
- [ ] `ExpiresAt` に基づく lookup / sweep を実装
- [ ] `TokenStorePath` と同一ディレクトリに `upstream_tokens.json` を置く

### [#116](https://github.com/scottlz0310/mcp-gateway/issues/116) upstream authorization flow

- [ ] upstream OAuth state store を TTL 付き in-memory で実装
- [ ] PKCE `code_verifier` / `code_challenge` を生成
- [ ] `/upstream/callback/{route-name}` を追加
- [ ] callback では state store から subject を復元し、middleware context に依存しない
- [ ] token endpoint から取得した token を `UpstreamTokenStore` に保存

### [#117](https://github.com/scottlz0310/mcp-gateway/issues/117) proxy integration

- [ ] `upstream_oauth` route では user-specific upstream token を `Authorization: Bearer` として注入
- [ ] token がない場合は upstream OAuth 認可フローへ誘導
- [ ] upstream 401 では該当 upstream token を削除し、gateway OAuth cache invalidation と混在させない
- [ ] `upstream_bearer_token_env` と既存 client token path の regression test を追加

### [#118](https://github.com/scottlz0310/mcp-gateway/issues/118) proactive refresh / 401 retry

- [ ] `ExpiresAt` が近い upstream token を proxy 注入前に refresh
- [ ] `ExpiresAt == zero` は期限不明として proactive refresh しない
- [ ] temporary refresh failure では既存 token を継続利用
- [ ] permanent refresh failure では token を削除して再認証へ誘導
- [ ] upstream 401 後に refresh / retry する
- [ ] 同一 subject x route の refresh を singleflight で排他

---

## 運用枠

### [#65](https://github.com/scottlz0310/mcp-gateway/issues/65) Dependency Dashboard

- [~] Renovate 管理 issue。open のまま維持する
- [ ] Renovate branch が発生した場合のみ、通常の依存更新 PR として個別に扱う
