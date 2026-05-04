# Tasks

`mcp-gateway` の継続的なタスク管理ファイル。各 issue の状態とサブタスク、依存関係を記録する。

## 凡例

- `[ ]` 未着手
- `[~]` 進行中
- `[x]` 完了
- `[-]` 保留 / 別 issue へ移管

---

## 推奨消化順（2026-05-04 更新）

### Phase 1 — 今すぐ着手（コード変更不要）

| 優先 | ISSUE | 理由 |
|---|---|---|
| 1 | **mcp-gateway #19** Compose ルーティング | ✅ 完了（PR #20 マージ済み） |
| 2 | **mcp-gateway #18** Copilot API 調査 | ✅ 完了（PR #21 マージ済み） |

### Phase 2 — #19 動作確認後

| 優先 | ISSUE | 状態/理由 |
|---|---|---|
| 3 | **mcp-gateway #16** Device Flow 直列化 | ✅ 完了（PR #31 マージ済み） |
| 4 | **copilot-review-mcp #12** AUTH_MODE=gateway | ✅ 完了（2026-05-04） |
| 5 | **mcp-gateway #15** ユーザーホワイトリスト | ⏭️ SKIP（ローカル Docker 運用継続、ホスティング移行時に再評価） |

### Phase 3 — インフラ整備（長期）

| 優先 | ISSUE | 理由 |
|---|---|---|
| 6 | **mcp-gateway #11** Config Persistence | 🎯 次ターゲット。暗号化方式の技術選択が先決 |
| 7 | **mcp-gateway #12** Setup Wizard | #11 完了が前提 |

### 保留維持

| ISSUE | 保留理由 |
|---|---|
| **#6** 汎用 OIDC | #18 結果次第で再評価 |
| **#5** env var 移行 | 追加プロバイダ確定まで YAGNI |
| **#4** fly.io OAuth | fly.io と直接調整が必要 |
| **#3** fly.io 調査 | 調査完了済み・保留 |

---

## Issue 一覧

---

### Phase 1

---

### [#19 feat: copilot-review-mcp を mcp-gateway 経由でルーティングする（Compose 設定 + 動作検証）](https://github.com/scottlz0310/mcp-gateway/issues/19)

**状態**: ✅ 完了（2026-04-28、PR #20 マージ済み）
**依存**: なし

copilot-review-mcp 側のコード変更ゼロで、`ROUTE_COPILOT_REVIEW=/mcp/copilot-review|http://copilot-review-mcp:8083` だけで動作する可能性が高い（Go ServeMux の subtree マッチングによる）。

#### サブタスク

- [x] mcp-docker 側の Compose 設定変更案作成（`ROUTE_COPILOT_REVIEW` 追加）
- [x] MCP クライアント（VS Code / Claude Desktop）での接続テスト
- [x] トークン二重検証の影響測定（キャッシュ効果の確認）
- [x] copilot-review-mcp への直接接続が壊れないことの確認（後方互換チェック）
- [x] README / CHANGELOG への反映

---

### [#18 spike: https://api.githubcopilot.com/mcp/ を upstream とした際の認証互換性調査](https://github.com/scottlz0310/mcp-gateway/issues/18)

**状態**: ✅ 完了（2026-04-28、PR #21 マージ済み）
**依存**: なし
**調査結果ドキュメント**: [`docs/spike-18-copilot-api-auth.md`](docs/spike-18-copilot-api-auth.md)

#### 主な発見

- `gho_` トークン（標準 GitHub OAuth）で MCP initialize 200 OK を確認
- upstream URL は `https://api.githubcopilot.com`（パスなし）と設定すること（`/mcp/` を含めると二重化）
- 複数ルートとの共存: `ROUTE_COPILOT=/mcp|https://api.githubcopilot.com` + `ROUTE_COPILOT_REVIEW=/mcp/copilot-review|http://copilot-review-mcp:8083`
- `WWW-Authenticate` ヘッダは、今回検証したクライアント/設定では書き換え不要だったが、401 時の `resource_metadata` は upstream URL を指すため将来的な書き換え検討余地あり
- copilot-cli の直接接続失敗はトークン形式の問題ではなく、OAuth App スコープ or MCP client 設定の問題

#### サブタスク

- [x] `https://api.githubcopilot.com/.well-known/oauth-authorization-server` の確認
- [x] `gho_...` トークンでの直接アクセステスト（`curl -H "Authorization: Bearer gho_..."`)
- [x] 必要なトークン形式・OAuth スコープの特定
- [x] per-upstream 認証設定の必要性評価
- [x] 調査結果を `docs/spike-18-copilot-api-auth.md` に記録

---

### Phase 2

---

### [#16 feat(auth): Device Flow の同時ポーリングを per-device で直列化して GitHub レート制限を回避](https://github.com/scottlz0310/mcp-gateway/issues/16)

**状態**: ✅ 完了（2026-04-30、PR #31 マージ済み）
**依存**: なし

同一 `device_code` への並列リクエストが GitHub を同時 polling → `slow_down` / レート制限を誘発する問題。

#### サブタスク

- [x] per-device mutex（または singleflight）の実装 → `AcquireDevicePolling` / `ReleaseDevicePolling`
- [x] 既存 `AuthorizeAndConsumeDevice` との整合性確認
- [x] テスト追加（並列リクエストのシミュレーション）
- [x] PR #31 Copilot レビュー対応・スレッドクローズ

---

#### [copilot-review-mcp #12 feat: AUTH_MODE=gateway 対応（mcp-gateway 経由モード・二重検証の排除）](https://github.com/scottlz0310/copilot-review-mcp/issues/12)

**状態**: ✅ 完了（2026-05-04）
**リポジトリ**: `scottlz0310/copilot-review-mcp`
**依存**: mcp-gateway #19

`AUTH_MODE=gateway` 環境変数で `X-Authenticated-User` ヘッダーを信頼するモードを追加。`GITHUB_CLIENT_ID/SECRET` を任意化。デフォルト（`standalone`）は後方互換維持。

#### サブタスク

- [x] `internal/middleware/auth.go` に `AuthMode` 分岐追加（+20〜30行）
- [x] `cmd/server/main.go` の `AUTH_MODE` 読み込みと条件分岐（+20行）
- [x] `AUTH_MODE=gateway` 時の `GITHUB_CLIENT_ID/SECRET` を optional に変更
- [x] テスト追加（gateway モード単体テスト）
- [x] README / CHANGELOG 更新

---

### [#15 feat: ホワイトリストによるアクセス制限（認証済みユーザーのフィルタリング）](https://github.com/scottlz0310/mcp-gateway/issues/15)

**状態**: ⏭️ SKIP（ローカル Docker 運用継続のため当面スキップ。ホスティング移行時に再評価）
**依存**: #11（Config Persistence）— #11 完了後に設定方式を再決定する

> **スキップ理由（2026-05-04）**: ホスティング環境での運用を当面行わないため優先度外とする。
> #11（Config Persistence）で YAML config 方式が確定した後、設計を見直して着手する。

#### サブタスク

- [ ] 設定方式の決定（env var / YAML config）
- [ ] middleware でのフィルタリング実装
- [ ] テスト追加
- [ ] README 更新

---

### Phase 3

---

### [#11 feat: Config Persistence Layer（env vars → YAML/SQLite 設定ファイル）](https://github.com/scottlz0310/mcp-gateway/issues/11)

**状態**: 🎯 次ターゲット（技術選択フェーズ）
**依存**: なし（独立着手可能）

> **方針変更（2026-05-04）**: ローカル Docker 運用継続を前提に着手。
> コンテナ起動時に `GITHUB_MCP_CLIENT_SECRET` 等が必須なため、これを config ファイルに永続化し
> 再起動時に env var 不要にすることを目的とする。
> SQLite・管理画面は引き続き後回し。まず YAML + シークレット暗号化 に絞る。

`mustEnv` によるクラッシュを撤廃し、設定を YAML で永続管理する。env vars はオーバーライド手段として維持（12-factor 互換）。

#### シークレット暗号化 — 技術選択（2026-05-04 確定）

**暗号化対象フィールド**

| フィールド | env var | 暗号化 |
|---|---|---|
| GitHub OAuth Client Secret | `GITHUB_MCP_CLIENT_SECRET` | ✅ 必須暗号化 |
| GitHub OAuth Client ID | `GITHUB_MCP_CLIENT_ID` | ❌ 平文（OAuth 安全モデル上公開前提） |
| tokens.json | — | ❌ 対象外（今回のスコープ外） |
| 将来の追加プロバイダ credential | TBD | ✅ 同様の方針で対応 |

**採用ライブラリ: `filippo.io/age`（X25519）**

**キー管理方針（優先順位）**

```
優先順位:  gateway.key  >  MCP_GATEWAY_MASTER_KEY  >  自動生成

1. `<keyPath>` が存在する → パース・検証して使用（MCP_GATEWAY_MASTER_KEY は無視）
   （keyPath = `MCP_GATEWAY_KEY_PATH` env > `./gateway.key`）
   ⛔ 存在するが読み取り不能・形式不正・空ファイル・パース失敗の場合は
      自動再生成・上書きを一切行わない。明確なエラーで起動を停止する。
      slog.Error("gateway.key exists but is invalid; refusing to overwrite to avoid data loss", "path", path, "err", err)
      os.Exit(1)
      ★ 新規生成してよいのは「gateway.key が存在しない」場合だけ。

2. 存在しない + MCP_GATEWAY_MASTER_KEY が設定されている
   → age のネイティブ API / 標準フォーマットに従って identity を
     決定論的に導出 → gateway.key（age 標準 identity 文字列形式）として保存
     ※ HKDF 出力を雑に private key として扱う独自実装は行わない
     ※ filippo.io/age の公開 API に沿った実装とする
     ※ PoC で API を確認してから実装方法を確定する（以下参照）

   ⚠️  filippo.io/age は任意バイト列から X25519Identity を決定論的に生成する
        公開 API を提供していない（ParseX25519Identity はテキスト形式専用）。
        X25519 方式に統一する方針のため、PoC での検証は以下に絞る:

   採用方式（X25519 統一・PoC 確認中）:
     HKDF で 32 bytes 導出 → bech32(AGE-SECRET-KEY-1...) エンコード
     → age.ParseX25519Identity() でパース → X25519 identity
     → age 標準テキスト形式（AGE-SECRET-KEY-1...）で gateway.key に保存
     → age CLI / age-keygen と互換

   PoC 確認事項:
     - HKDF → bech32 → ParseX25519Identity の往復が正常に動作すること
     - 同じ master key から毎回同じ identity が得られること（決定論的性）
     - 別の master key では復号できないこと

   ⛔ ScryptIdentity（候補 A）は採用しない:
      AGE-SECRET-KEY-1 形式で保存できず、key file 方式と passphrase 方式が
      混在して設計が濁るため #11 スコープから除外する。

   MCP_GATEWAY_MASTER_KEY からの決定論的生成が難しいと判明した場合:
     → その機能のみ別 issue / 別 PR に切り出す
     → #11 ではランダム生成（age.GenerateX25519Identity()）した gateway.key を
        volume に保存する方式で先行実装する

3. どちらも無い → age.GenerateX25519Identity() で新規生成 → gateway.key 保存

⚠️  gateway.key が存在する場合は MCP_GATEWAY_MASTER_KEY を無視する
    （誤ってキーを変えることで復号不能になる事故を防止）
⚠️  gateway.key を失った場合、既存の暗号化済み config は復号不能。
    MCP_GATEWAY_MASTER_KEY を使って派生させた場合は同じ値で再生成可能。
    → README に「キーファイルのバックアップは Docker volume のバックアップと同義」と明記する。
```


**gateway.key のファイル形式**

```
age の標準 identity 文字列形式（AGE-SECRET-KEY-1...）でテキスト保存（X25519 方式に統一）。
age-keygen の出力と同じ形式:
  # created: 2026-05-04T22:00:00+09:00
  # public key: age1xxxx...
  AGE-SECRET-KEY-1XXXX...
→ age CLI ツールとの互換性あり、手動での確認・バックアップが容易。
独自バイナリ形式・独自 JSON 形式・独自 Base64 形式は使わない。
```


**env var 命名**

```
MCP_GATEWAY_MASTER_KEY  ← 正式名（優先）
MCP_MASTER_KEY          ← 互換 alias（どちらも設定されている場合は MCP_GATEWAY_MASTER_KEY を優先）
```

README に以下を明記する：
- 十分に長いランダム値（推奨: 32 bytes 以上のランダム値を base64 エンコードした文字列 ≈ 44 文字）を使用すること
  （例: `openssl rand -base64 32`）
- **漏えいリスク（重要）**: `MCP_GATEWAY_MASTER_KEY` が漏えいした場合、
  暗号化済み `config.yaml`（ENC[...]）を持つ攻撃者は `gateway.key` がなくても
  同じ master key から復号キーを再生成できるため**即座に復号可能**になる。
  漏えい時は MCP_GATEWAY_MASTER_KEY を変更し、gateway.key を削除して再初期化すること。
  また、ENC[...] の中身も新しいキーで再暗号化すること。
- gateway.key が存在する場合は MCP_GATEWAY_MASTER_KEY は無視されること

**ファイルパーミッション**

```
gateway.key: mode 0600 で保存（os.WriteFile / os.Chmod）
  → Linux/macOS: 0600 が有効
  → Windows volume 等で chmod が効かない場合: 警告ログを出力してベストエフォートで続行
    slog.Warn("could not set restrictive permissions on key file", "path", path, "err", err)
    ※ err メッセージのみ。キー内容はログに出さない
```

**シークレットのログ出力禁止ルール**

以下を絶対にログに出さない：
- シークレット値の平文（`GITHUB_MCP_CLIENT_SECRET` 等）
- 復号後の値
- env var の値
- `gateway.key` の内容
- `ENC[...]` の全文

エラーログには「フィールド名」「ファイルパス」「エラー種別」のみ含める。

**config.yaml の secret フィールド移行ロジック（起動時に毎回評価）**

```
github_client_secret の値を確認:

1. "ENC[age:]..." 形式 → age で復号して使用
2. 平文が config.yaml にある → age で暗号化して config.yaml に書き戻し、再起動なしで続行
3. config.yaml にキー自体が無い or 空
   → GITHUB_MCP_CLIENT_SECRET env var を確認
   → env var が設定されている → age で暗号化して config.yaml に保存し続行
   → env var も無い → 明確なエラーで起動失敗
     slog.Error("github_client_secret is required: set GITHUB_MCP_CLIENT_SECRET env var or provide an encrypted value in config.yaml")
     os.Exit(1)

      ⚠️ #12 Setup Wizard との連携（将来対応）:
         #12 実装時は「secret 未設定 = セットアップ未完了」状態として
         os.Exit(1) の代わりにセットアップモードへ遷移する。
         現時点（#11 単独実装）では #12 との結合は行わない。
```

> **シークレットのローテーション手順**
>
> `ENC[...]` が config.yaml に保存された後、`GITHUB_MCP_CLIENT_SECRET` を更新するには:
> 1. config.yaml の `github_client_secret:` 行を削除またはコメントアウト
> 2. 新しい値を `GITHUB_MCP_CLIENT_SECRET` env var にセット
> 3. 再起動 → 移行ロジックのステップ 3 が新値を暗号化保存する
>
> ⚠️ 一度 `ENC[...]` が保存されると env var は **再起動時に再読み込みされない**（意図的な設計）。
> 上書き変更は必ず上記手順で行うこと。

**ファイルレイアウト（/data/ volume）**

```
/data/
  gateway.key    ← age identity 秘密鍵（mode 0600）← 必ず volume mount 対象
  config.yaml    ← github_client_secret: "ENC[age:]<base64-ciphertext>" を含む YAML
  tokens.json    ← 既存（変更なし・今回のスコープ外）
```

**config.yaml イメージ**

```yaml
auth:
  github_client_id: "Ov23liXXXXXX"                     # 平文
  github_client_secret: "ENC[age:]<base64-ciphertext>"  # age 暗号化済み（base64 バイナリ暗号文）
gateway:
  base_url: "http://localhost:8080"
  port: "8080"
  oauth_scopes: "repo,user"
```

> ⚠️ `age1...` は age の公開鍵（受信者）のプレフィックスであり、暗号文ではない。
> `ENC[...]` の中身は age 暗号文を base64 エンコードしたバイナリ（`ENC[age:]<base64-ciphertext>` 形式で統一）。
> アーマードテキスト（`-----BEGIN AGE ENCRYPTED FILE-----` 形式）をそのまま埋め込む方式は採用しない。

#### サブタスク

- [x] 暗号化ライブラリ選定（`filippo.io/age` 採用確定）・キー管理方針・追加制約の方針決定（完了）
- [ ] キー導出方式の確定（X25519 統一・PoC 必須）
  - HKDF → 32 bytes → bech32 エンコード → `age.ParseX25519Identity()` で X25519 identity 生成
  - ScryptIdentity は不採用（AGE-SECRET-KEY-1 形式で保存不可のため #11 スコープ外）
  - 決定論的生成が困難と判明した場合は別 issue 化し、#11 はランダム生成で先行実装
- [ ] `filippo.io/age` を go.mod に追加（`go get filippo.io/age`）と PoC
  - HKDF → bech32 → `age.ParseX25519Identity()` の往復が動作するか確認
  - **PoC で検証すること（運用事故チェックリスト）**:
    1. 同じ master key から毎回同じ identity が得られること（決定論的性）
    2. 別の master key では復号できないこと
    3. gateway.key の AGE-SECRET-KEY-1... 形式での保存・読み込みが往復で一致すること
    4. gateway.key が不正形式・空・存在するが読み取り不能の場合に起動エラーになること（上書きしないこと）
- [ ] `internal/config/` パッケージ新設
  - Config 構造体・YAML 読み書き（`gopkg.in/yaml.v3`）
  - `LoadKey(keyPath, masterKey string) (KeyMaterial, error)` — 優先順位でキーを解決・保存

    ```go
    // KeyMaterial は復号 + 暗号化の両 interface を保持する。
    // age.Identity は復号のみ、age.Recipient は暗号化のみのため両方必要。
    type KeyMaterial struct {
        Decrypt age.Identity   // DecryptField で使う復号側（age.Identity は復号専用）
        Encrypt age.Recipient  // EncryptField で使う暗号化側
    }
    // PoC 結果に応じた具体型（X25519 統一）:
    //   Decrypt = *X25519Identity, Encrypt = identity.Recipient()
    ```

    - gateway.key 破損時は `errKeyCorrupt` 系エラーを返し、呼び出し元で `os.Exit(1)`
    - MCP_GATEWAY_MASTER_KEY の長さが 32 bytes 未満の場合はエラー
  - `EncryptField(km KeyMaterial, plaintext string) (string, error)` — `ENC[age:]<base64-ciphertext>` 形式（正確なフォーマットは PoC で確定）
  - `DecryptField(km KeyMaterial, ciphertext string) (string, error)` — フィールド復号
  - `MigrateSecret(cfg *Config, km KeyMaterial) error` — 移行ロジック（上記 3 ケース）
  - env override マージ（12-factor 互換）
  - 0600 ファイル保存・Windows ベストエフォート警告
  - ログ出力禁止ルールに従うこと（シークレット値を一切 slog に渡さない）
- [ ] 設定ファイルパス解決（`MCP_CONFIG_FILE` env > `./config.yaml`）
  - Docker Compose では `MCP_CONFIG_FILE=/data/config.yaml` を明示指定する
  - `/data/config.yaml` をデフォルトにすると非 Docker 環境（`go run`・bare binary）で起動失敗するため、デフォルトはカレントディレクトリ
- [ ] キーファイルパス解決（`MCP_GATEWAY_KEY_PATH` env > `./gateway.key`）
  - Docker Compose では `MCP_GATEWAY_KEY_PATH=/data/gateway.key` を明示指定する
  - `/data/gateway.key` をデフォルトにすると非 Docker 環境で起動失敗するため、デフォルトはカレントディレクトリ
- [ ] `cmd/server/main.go` の `mustEnv` を config ロードに置き換え
  - `MCP_GATEWAY_MASTER_KEY` / `MCP_MASTER_KEY` alias の読み込み
- [ ] `internal/router/router.go` の `ParseEnv()` を config ベース実装に切り替え
- [ ] テスト — 以下のケースをすべてカバーすること:
  - `gateway.key` あり + env var あり → `gateway.key` 優先・env var は無視
  - `gateway.key` なし + `MCP_GATEWAY_MASTER_KEY` あり → 決定論的に生成・保存（同じ key で再実行すると同じ identity）
  - `gateway.key` なし + env var なし → ランダム生成・保存
  - `gateway.key` 不正（空・形式不正・権限エラー）→ 自動上書きせずエラー終了
  - `ENC[...]` 復号成功
  - 平文 secret が config.yaml にある → 暗号化して書き戻し
  - secret なし + `GITHUB_MCP_CLIENT_SECRET` env var あり → 暗号化保存
  - secret なし + env var なし → 明確なエラー
  - ログに secret 値・ENC 全文・key 内容が含まれないこと
  - `MCP_GATEWAY_MASTER_KEY` が 32 bytes 未満 → エラー
- [ ] README.md（キーバックアップ警告・`MCP_GATEWAY_MASTER_KEY` のリスク・最低長・gateway.key 破損時の対応） / CHANGELOG.md 更新

---

### [#12 feat: First-run Setup Wizard（初回デプロイ時のインタラクティブ設定フロー）](https://github.com/scottlz0310/mcp-gateway/issues/12)

**状態**: 未着手
**依存**: #11（Config Persistence Layer）

設定ファイルが存在しない初回起動時に `/setup` エンドポイントを自動活性化し、ブラウザ or CLI で初期設定を完了できるようにする。

起動フロー:
```
設定なし → setup_token を stdout に出力 → GET /setup?token=<token> → POST /setup → 設定完了 → 通常起動
```

#### サブタスク

- [ ] `internal/setup/` パッケージ新設（token 生成・検証・一度限り保証）
- [ ] `setup_completed` フラグの config 統合（#11 依存）
- [ ] `GET /setup` / `POST /setup` ハンドラ実装
- [ ] 起動ログへの setup_token 出力（`log/slog`）
- [ ] 未 setup 状態での通常ルートのレスポンス
- [ ] HTTPS チェック（production 判定）
- [ ] テスト / README.md（first-run guide 書き換え） / CHANGELOG.md 更新

---

### 保留中

---

### [#6 feat: 汎用 OIDC（OpenID Connect）プロバイダサポート](https://github.com/scottlz0310/mcp-gateway/issues/6)

**状態**: 保留（2026-04-27）
**依存**: #2
**保留理由**: Entra ID は DCR 未サポートで MCP OAuth 2.1 仕様と不適合。対象 MCP サーバーが具体的に決まるまで見送り（YAGNI）。**#18 の結果次第で再評価**。

#### サブタスク

- [-] `internal/auth/provider/oidc.go` 実装（保留）
- [-] OIDC Discovery + JWKS フェッチ（保留）
- [-] ID Token 検証（署名・クレーム）（保留）
- [-] 環境変数追加（`OAUTH_ISSUER_URL`, `OAUTH_AUDIENCE` 等）（保留）
- [-] Auth0 / Keycloak での結合テスト（保留）

---

### [#5 refactor: 環境変数を OAUTH_* 系に移行・GITHUB_MCP_* を deprecate](https://github.com/scottlz0310/mcp-gateway/issues/5)

**状態**: 保留（2026-04-27）
**依存**: #2
**保留理由**: 追加プロバイダがすべて保留・クローズとなったため優先度低下。プロバイダ追加が確定した時点で再開。

#### サブタスク

- [-] `OAUTH_PROVIDER` / `OAUTH_CLIENT_ID` / `OAUTH_CLIENT_SECRET` / `OAUTH_SCOPES` を導入（保留）
- [-] `GITHUB_MCP_*` の後方互換ロジック追加（warning 付き）（保留）
- [-] README 環境変数表の更新（保留）
- [-] CHANGELOG に移行ガイド記載（保留）

---

### [#4 feat: fly.io OAuth プロバイダ実装](https://github.com/scottlz0310/mcp-gateway/issues/4)

**状態**: 保留（2026-04-27）
**依存**: #2, #3
**保留理由**: fly.io OAuth（Sign in with Fly）は Extensions Provider 専用であり、開発用 client_id/client_secret の self-service 登録手段がない。fly.io と直接調整が必要なため、プロダクト品質が整うまで後回し。代替 OAuth プロバイダの検討を優先する。

#### サブタスク

- [-] `internal/auth/provider/flyio.go` 実装（保留）
- [-] `internal/auth/provider/factory.go` の `flyio` 分岐追加（保留）
- [-] 単体テスト追加（保留）
- [-] README に fly.io 設定例追記（保留）

---

### [#3 spike: fly.io 認証方式の調査（OAuth Provider vs Macaroon Tokens）](https://github.com/scottlz0310/mcp-gateway/issues/3)

**状態**: 調査完了（2026-04-27）
**依存**: なし

**結論**: Sign in with Fly（OAuth 2.0）を Issue #4 で採用。Macaroon は Provider IF 不適合のため対象外。Provider IF（#2 で確定）に変更不要。詳細は Issue #3 本文参照。

#### サブタスク

- [x] fly.io OAuth Provider の `authorize` / `token` / userinfo エンドポイント仕様確認
- [x] fly.io OAuth App 登録手段の確認（self-service 不可・fly.io と直接調整）
- [x] Fly Tokens（Macaroon）検証手段の確認（`superfly/macaroon` + tkdb・外部利用非推奨）
- [x] mcp-gateway のユースケースに必要な系統の確定（Sign in with Fly）
- [-] 調査メモ作成（`docs/spikes/flyio-auth.md`）→ Issue #3 本文に集約
- [x] Issue #2 / #4 へのフィードバック（IF 変更不要・#4 前提条件を本文に記載）

---

### 完了 / クローズ

---

### [#2 refactor: OAuth プロバイダ抽象化（Provider インターフェース導入・GitHub 実装の移植）](https://github.com/scottlz0310/mcp-gateway/issues/2)

**状態**: ✅ 完了（2026-04-28、PR #7 マージ済み）
**依存**: なし

GitHub 固定の OAuth フローを `Provider` インターフェースに抽象化。本 issue は **GitHub-only リファクタ**に限定し、外部 IF（環境変数・エンドポイント・OAuth フロー）は 100% 維持する。

#### サブタスク

- [x] `internal/auth/provider/provider.go` — `Provider` IF + `Identity` 構造体
- [x] `internal/auth/provider/errors.go` — `UpstreamError` 移設
- [x] `internal/auth/provider/github.go` — GitHub 実装（既存ロジック移植）
- [x] `internal/auth/provider/factory.go` — `New(cfg) (Provider, error)`
- [x] `internal/auth/provider/mock.go` — テスト用 Mock
- [x] `internal/auth/provider/github_test.go` — GitHub 実装の単体テスト
- [x] `internal/auth/handler.go` — Provider 委譲、Config から GitHub 専用フィールド除去
- [x] `internal/middleware/auth.go` — `ContextKeyIdentity` へ rename
- [x] `internal/proxy/handler.go` — `X-Authenticated-User` 注入（`X-GitHub-Login` も互換併存）
- [x] `cmd/server/main.go` — Provider factory 経由で生成
- [x] `README.md` — 内部設計の補足
- [x] `CHANGELOG.md` — 変更履歴記載
- [x] テスト緑（`go test ./...`）

---

### [#8 feat: Google OAuth 2.0 プロバイダ実装](https://github.com/scottlz0310/mcp-gateway/issues/8)

**状態**: クローズ（2026-04-27・YAGNI）
**理由**: Google 公式 MCP サーバーは OAuth + Streamable HTTP を既に内包。対象 MCP サーバーが具体的に決まるまで見送り。

---

### [#22 feat: per-route auth bypass via ROUTE_<NAME>=<prefix>|<upstream>|auth=none](https://github.com/scottlz0310/mcp-gateway/issues/22)

**状態**: ✅ 完了（2026-04-28、PR #23 マージ済み）
**依存**: なし

`ROUTE_<NAME>` 環境変数の第3セグメントに `auth=none` を指定すると、そのルートで認証ミドルウェアをスキップする。Copilot API の like public upstream に使用。

---

### [#24 feat: OAuth トークン/セッション状態の永続化（再認証スキップ）](https://github.com/scottlz0310/mcp-gateway/issues/24)

**状態**: ✅ 完了（2026-04-28、PR #25 マージ済み）
**依存**: なし

`MCP_GATEWAY_TOKEN_STORE_PATH` 環境変数でJSON ファイルベースのトークンストアを有効化。ゲートウェイ再起動後もMCPクライアントの再認証不要。

---

### [#26 fix: リフレッシュトークン切れによる「session not found」エラー調査と対処](https://github.com/scottlz0310/mcp-gateway/issues/26)

**状態**: ✅ 完了（2026-04-30、PR #27 マージ済み）
**依存**: なし

RFC 6749 §6 の `grant_type=refresh_token` を実装。アクセストークン期限切れ時にリフレッシュトークンで再発行できるようにした（ローテーション付き・並列リクエスト対応）。

---

### [#28 fix: Dockerfile `/data` ディレクトリを nonroot 所有で作成](https://github.com/scottlz0310/mcp-gateway/issues/28)

**状態**: ✅ 完了（2026-04-30、PR #29 マージ済み）
**依存**: なし

builder ステージで `/data` を `nonroot:nonroot` 所有で作成し、init コンテナなしで永続ストアが書き込み可能になった。

---

### [#10 spike: Device Authorization Grant を gateway レイヤーで実装する可能性調査](https://github.com/scottlz0310/mcp-gateway/issues/10)

**状態**: ✅ 完了（2026-04-28、PR #14 マージ済み）
**依存**: #2（完了済み）

`POST /device_authorization` + `/token` の device_code grant を実装済み。アーキテクチャは **gateway が Device Grant を実行する**方式（MCP Client → mcp-gateway → GitHub）。

#### サブタスク

- [x] GitHub Device Grant エンドポイント（`client_secret` 要否）の確認
- [x] gateway 内 Device Grant フロー設計（`POST /device_authorization`・`POST /token` `grant_type=urn:ietf:params:oauth:grant-type:device_code`）
- [x] MCP Authorization Server Metadata への `device_authorization_endpoint` 追加
- [x] 既存 Authorization Code Flow との共存設計・実装
