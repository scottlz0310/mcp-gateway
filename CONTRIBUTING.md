# Contributing

## Logging & Secrets

トークン・シークレット様の値(アクセストークン、リフレッシュトークン、client secret、API キー等)を `slog` の引数やエラーメッセージに生値のまま渡さないこと。ログでトークンを識別する必要がある場合は、既存の sha256 ベースのヘルパーを使用する:

- `internal/auth`: `tokenFingerprint`
- `internal/proxy`: `tokenHash`
- `internal/upstreamoauth`: `subjectHash`

エラー文字列に HTTP レスポンスボディを含める場合は、非 2xx のエラーレスポンスに限定し、`io.LimitReader(resp.Body, 256)` で切り詰めること(トークンを含む成功レスポンスをエラーに載せない)。アクセスログにはクエリ文字列を含めない(`r.URL.Path` を使う)。

唯一の例外は setup mode のワンタイムトークン提示(`cmd/server/main.go`)。例外の根拠と監査結果は [docs/token-log-audit.md](docs/token-log-audit.md) を参照。例外を新設する場合は同ドキュメントの更新を必須とする。

## Release & Tag Naming

### Prerelease tags

Prerelease tags **must** follow SemVer pre-release format (containing `-`), e.g. `v1.0.0-rc.1`.

This is required because `docker/metadata-action` with `latest=auto` adds `:latest` only to non-prerelease semver tags. A tag like `v1.0.0-hotfix` without a pre-release identifier may not be recognized as a prerelease by some semver libraries, causing `:latest` to be updated unintentionally.

Valid: `v1.0.0-rc.1`, `v1.2.0-beta.2`, `v2.0.0-alpha.1`  
Invalid: `v1.0.0-hotfix`, `v1.0.0.rc1`
