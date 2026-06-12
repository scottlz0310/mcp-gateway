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

// NormalizeOAuthErrorCode は外部入力の error code を監査ログ向け識別子へ制限する。
func NormalizeOAuthErrorCode(code string) string {
	code = strings.TrimSpace(code)
	if code == "" {
		return ""
	}
	if len(code) > 64 {
		return "invalid_error_code"
	}
	for _, char := range code {
		if char >= 'a' && char <= 'z' ||
			char >= 'A' && char <= 'Z' ||
			char >= '0' && char <= '9' ||
			char == '_' || char == '-' || char == '.' {
			continue
		}
		return "invalid_error_code"
	}
	return code
}
