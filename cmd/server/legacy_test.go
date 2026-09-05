package main

import "testing"

func TestResolveLegacyAdapter(t *testing.T) {
	for _, tc := range []struct {
		name, env                string
		set, yaml, want, invalid bool
	}{
		{name: "default"},
		{name: "yaml", yaml: true, want: true},
		{name: "env on", env: "true", set: true, want: true},
		{name: "env off overrides yaml", env: "false", set: true, yaml: true},
		{name: "invalid", env: "typo", set: true, invalid: true},
		{name: "empty", set: true, invalid: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := resolveLegacyAdapter(tc.yaml, func(key string) (string, bool) {
				if key != "GATEWAY_LEGACY_ADAPTER_ENABLED" {
					t.Fatalf("設定キーが不正: %s", key)
				}
				return tc.env, tc.set
			})
			if got != tc.want || (err != nil) != tc.invalid {
				t.Fatalf("got=%t err=%v", got, err)
			}
		})
	}
}
