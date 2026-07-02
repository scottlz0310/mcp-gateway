package provider

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
)

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

// OAuthError は provider response body や error description の生値を保持せず、
// 機械判定に必要な provider failure metadata だけを表す。
type OAuthError struct {
	Provider   string
	Operation  string
	Code       string
	HTTPStatus int
	Transient  bool
	Err        error
}

func (e *OAuthError) Error() string {
	message := fmt.Sprintf("%s OAuth %s failed", e.Provider, e.Operation)
	if e.Code != "" {
		message += ": " + e.Code
	}
	if e.HTTPStatus != 0 {
		message += fmt.Sprintf(" (status %d)", e.HTTPStatus)
	}
	return message
}

func (e *OAuthError) Unwrap() error {
	return e.Err
}

// ErrorDetails は認証監査イベントで使用する安定 field を抽出する。
func ErrorDetails(err error) (oauthCode string, httpStatus int, transient bool) {
	var oauthErr *OAuthError
	if errors.As(err, &oauthErr) {
		oauthCode = NormalizeOAuthErrorCode(oauthErr.Code)
		httpStatus = oauthErr.HTTPStatus
		transient = oauthErr.Transient
	}
	var upstreamErr *UpstreamError
	if errors.As(err, &upstreamErr) {
		transient = true
	}
	return oauthCode, httpStatus, transient
}

func decodeOAuthErrorCode(body io.Reader) string {
	var payload struct {
		Error string `json:"error"`
	}
	if err := json.NewDecoder(io.LimitReader(body, 4<<10)).Decode(&payload); err != nil {
		return ""
	}
	return NormalizeOAuthErrorCode(payload.Error)
}

// knownOAuthErrorCodes は監査ログ・エラー文字列へそのまま残してよい既知の
// OAuth / OIDC error code の集合。RFC 6749 §4.1.2.1・§5.2、RFC 8628 §3.5、
// OIDC Core §3.1.2.6、GitHub 固有コードをカバーする。
// NormalizeOAuthErrorCode の冪等性のため "unknown_error" 自身も含む。
var knownOAuthErrorCodes = map[string]struct{}{
	// RFC 6749 §4.1.2.1 (authorization endpoint) / §5.2 (token endpoint)
	"invalid_request":           {},
	"invalid_client":            {},
	"invalid_grant":             {},
	"unauthorized_client":       {},
	"unsupported_grant_type":    {},
	"invalid_scope":             {},
	"access_denied":             {},
	"unsupported_response_type": {},
	"server_error":              {},
	"temporarily_unavailable":   {},
	// RFC 8628 §3.5 (device flow)
	"authorization_pending": {},
	"slow_down":             {},
	"expired_token":         {},
	// RFC 6750 §3.1 (Bearer token) — invalid_token は本パッケージの
	// ValidateToken 分類コードとしても内部生成される
	"invalid_token":      {},
	"insufficient_scope": {},
	// 内部生成の分類コード(github.go / oidc.go の ValidateToken)
	"rate_limited": {},
	// OIDC Core §3.1.2.6
	"interaction_required":       {},
	"login_required":             {},
	"account_selection_required": {},
	"consent_required":           {},
	"invalid_request_uri":        {},
	"invalid_request_object":     {},
	"request_not_supported":      {},
	"request_uri_not_supported":  {},
	"registration_not_supported": {},
	// GitHub 固有
	"incorrect_client_credentials": {},
	"redirect_uri_mismatch":        {},
	"bad_verification_code":        {},
	"incorrect_device_code":        {},
	"device_flow_disabled":         {},
	"application_suspended":        {},
	"unknown_error":                {},
}

// NormalizeOAuthErrorCode は外部入力の error code を監査ログ向け識別子へ制限する。
// 既知の OAuth / OIDC error code のみ小文字化して返し、未知値は固定値
// "unknown_error" へ落とす。文字種・長さの制限だけでは、AS が秘密値を
// error フィールドへ反映した場合に生値がログへ残るため fail-closed とする。
func NormalizeOAuthErrorCode(code string) string {
	code = strings.ToLower(strings.TrimSpace(code))
	if code == "" {
		return ""
	}
	if _, ok := knownOAuthErrorCodes[code]; ok {
		return code
	}
	return "unknown_error"
}
