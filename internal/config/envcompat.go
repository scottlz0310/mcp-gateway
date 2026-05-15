package config

import (
	"log/slog"
	"os"
	"strings"
	"sync"
)

// legacyEnvWarned tracks which deprecated environment variables have already
// emitted a deprecation warning so that operators only see the message once
// per process lifetime even when the variable is consulted multiple times.
var legacyEnvWarned sync.Map

// resetLegacyEnvWarnedForTest clears the legacy-env warning tracker. Tests use
// it to keep deprecation-warning assertions independent of each other; it is
// not exported because production code must not reset the once-per-process
// guarantee.
func resetLegacyEnvWarnedForTest() {
	legacyEnvWarned.Range(func(key, _ any) bool {
		legacyEnvWarned.Delete(key)
		return true
	})
}

// warnLegacyEnvOnce logs a deprecation warning for a legacy env var the first
// time it is observed. When ignored is true, the warning indicates that the
// legacy variable was ignored because the canonical variable is also set;
// otherwise, the warning indicates the legacy variable is in use.
//
// The warning is emitted at most once per legacy variable per process.
func warnLegacyEnvOnce(legacyKey, canonicalKey string, ignored bool) {
	if _, loaded := legacyEnvWarned.LoadOrStore(legacyKey, true); loaded {
		return
	}
	if ignored {
		slog.Warn("legacy env var ignored because canonical env var is set",
			"legacy", legacyKey,
			"canonical", canonicalKey,
			"hint", legacyKey+" will be removed in a future major release",
		)
		return
	}
	slog.Warn("legacy env var is deprecated; use canonical env var instead",
		"legacy", legacyKey,
		"canonical", canonicalKey,
		"hint", legacyKey+" will be removed in a future major release",
	)
}

// ResolveOAuthEnv returns the value of the canonical OAUTH_* environment
// variable, falling back to a deprecated legacy variable when the canonical
// one is unset. The boolean ok indicates whether either variable was set to a
// non-empty value.
//
// Priority:
//  1. canonicalKey set and non-empty → returned (legacy ignored with warning)
//  2. only legacyKey set and non-empty → returned with deprecation warning
//  3. neither set → ("", false)
func ResolveOAuthEnv(canonicalKey, legacyKey string) (value string, ok bool) {
	v, _, ok := resolveOAuthEnvSourced(canonicalKey, legacyKey)
	return v, ok
}

func resolveOAuthEnvSourced(canonicalKey, legacyKey string) (value, source string, ok bool) {
	canonical, canonicalSet := lookupNonEmptyEnv(canonicalKey)
	legacy, legacySet := lookupNonEmptyEnv(legacyKey)
	switch {
	case canonicalSet && legacySet:
		warnLegacyEnvOnce(legacyKey, canonicalKey, true)
		return canonical, canonicalKey, true
	case canonicalSet:
		return canonical, canonicalKey, true
	case legacySet:
		warnLegacyEnvOnce(legacyKey, canonicalKey, false)
		return legacy, legacyKey, true
	default:
		return "", "", false
	}
}

func lookupNonEmptyEnv(key string) (string, bool) {
	v, ok := os.LookupEnv(key)
	if !ok {
		return "", false
	}
	if strings.TrimSpace(v) == "" {
		return "", false
	}
	return v, true
}
