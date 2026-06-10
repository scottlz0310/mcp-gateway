# Contributing

## Release & Tag Naming

### Prerelease tags

Prerelease tags **must** follow SemVer pre-release format (containing `-`), e.g. `v1.0.0-rc.1`.

This is required because `docker/metadata-action` with `latest=auto` adds `:latest` only to non-prerelease semver tags. A tag like `v1.0.0-hotfix` without a pre-release identifier may not be recognized as a prerelease by some semver libraries, causing `:latest` to be updated unintentionally.

Valid: `v1.0.0-rc.1`, `v1.2.0-beta.2`, `v2.0.0-alpha.1`  
Invalid: `v1.0.0-hotfix`, `v1.0.0.rc1`
