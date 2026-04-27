package provider

// UpstreamError represents a transient failure contacting an OAuth provider's
// API (network error, 5xx response). Callers (e.g. middleware) use this to
// return 503 Service Unavailable instead of 401 Unauthorized so that clients
// retry rather than treat the token as invalid.
type UpstreamError struct {
	Err error
}

func (e *UpstreamError) Error() string         { return e.Err.Error() }
func (e *UpstreamError) Unwrap() error         { return e.Err }
func (e *UpstreamError) IsUpstreamError() bool { return true }
