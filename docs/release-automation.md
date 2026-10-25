# リリースの準備と公開

リリースは release-automate の固定 SHA の prepare / publish / finalize を使用する。
タグ push 起点の公開は廃止し、成果物生成を publish caller の依存ジョブで接続する。

## 準備

1. 利用者が対象版と実リリースを指示した後、既定ブランチの `Prepare Release` に
   先頭に `v` のない SemVer `MAJOR.MINOR.PATCH`（RC・build metadata 可）を指定する。
2. Release bot が準備 PR を作成する。版定数はないため `bump_strategy: none` とし、
   `CHANGELOG.md` と `CHANGELOG.ja.md` の Unreleased を同時に確定する。
3. 原稿・比較リンクを確認し、同一 HEAD の CI・独立レビュー・未解決スレッドを確認する。
4. 公開する版・コミット・内容を利用者へ提示し、公開を含む許可後に squash merge する。
   件名は `chore(release): vX.Y.Z` とする。通常の導入 PR のマージでは公開しない。

## 公開

`release.yml` はリリースコミットだけを受け、次を実行する。

1. トリガー SHA にタグと draft Release を作成し、日本語 CHANGELOG の該当版を本文にする。
2. 同じ SHA で `go vet` と race 付きテストを実行し、amd64/arm64 イメージを GHCR に公開する。
   正式版では版・minor 系列・latest のタグを付け、RC には latest を付けない。
3. 公開された版タグの digest が build の返却値と一致し、manifest が linux/amd64 と
   linux/arm64 を含むことを再取得で確認する。
4. 検証成功後だけ finalize で公開し、共通 workflow が Docker digest・対象 SHA・run・
   依存ジョブの成功を本文へ追記する。GitHub 自動生成の What's Changed は併記しない。

prepare には Organization の `RELEASE_BOT_CLIENT_ID` / `RELEASE_BOT_PRIVATE_KEY` を渡す。
公開・GHCR 配布には実行 repo の `GITHUB_TOKEN` を使い、新しい認証方式は追加しない。

検証失敗時は draft を保持する。同じ run の failed jobs を原因解消後に再実行する。
finalize の本文追記だけが失敗した場合、公開済みでも failed finalize の再実行で追記できる。
別 SHA へのタグの移動・削除、別版での自動的な再試行は行わない。
公開後はタグの SHA、Release の対象・公開状態・日本語本文、GHCR digest と manifest を確認する。
manifest の確認はサーバーの実機動作確認とは区別する。
