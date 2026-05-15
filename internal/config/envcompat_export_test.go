package config

// resetLegacyEnvWarnedForTest clears the legacy-env warning tracker. Tests use
// it to keep deprecation-warning assertions independent of each other. It
// lives in a *_test.go file so it is excluded from production builds.
func resetLegacyEnvWarnedForTest() {
	legacyEnvWarned.Range(func(key, _ any) bool {
		legacyEnvWarned.Delete(key)
		return true
	})
}
