// export_test.go exposes internal helpers for use in external test packages.
// This file is compiled only during testing.
package setup

import "time"

// NewWithTTL creates a Manager with a custom TTL, for use in tests only.
func NewWithTTL(ttl time.Duration) (*Manager, error) {
	return newManager(ttl)
}
