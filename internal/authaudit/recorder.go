package authaudit

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	DefaultMaxSizeMB    = 10
	DefaultMaxBackups   = 5
	DefaultMaxAgeDays   = 30
	DefaultFailureLimit = 100

	auditEventName = "oauth_audit"
)

// Event は JSON Lines と internal 診断 API で共有する OAuth 監査イベントである。
// token、authorization code、state、secret、provider body の生値を保持できる
// field は意図的に定義しない。
type Event struct {
	Timestamp  time.Time `json:"timestamp"`
	Event      string    `json:"event"`
	Phase      string    `json:"phase"`
	Provider   string    `json:"provider"`
	Result     string    `json:"result"`
	ErrorClass string    `json:"error_class"`
	OAuthError string    `json:"oauth_error"`
	HTTPStatus int       `json:"http_status"`
	Message    string    `json:"message"`
	TokenHash  string    `json:"token_hash,omitempty"`
}

// Recorder は auth package と internal API が利用する監査機能の境界である。
type Recorder interface {
	Record(Event) error
	RecentFailures() []Event
	Path() string
	Close() error
}

// Config は監査ログの保存先と保持設定を表す。
type Config struct {
	Path            string
	MaxSizeBytes    int64
	MaxBackups      int
	MaxAge          time.Duration
	FailureCapacity int
}

// FromEnvironment は OS 別の既定 path と保持設定を解決する。
// 不正な明示設定は既定値へ fallback せずエラーにする。
func FromEnvironment() (Config, error) {
	path, err := ResolvePath(strings.TrimSpace(os.Getenv("MCP_GATEWAY_AUTH_AUDIT_LOG_PATH")))
	if err != nil {
		return Config{}, err
	}
	maxSizeMB, err := positiveEnvInt("MCP_GATEWAY_AUTH_AUDIT_MAX_SIZE_MB", DefaultMaxSizeMB)
	if err != nil {
		return Config{}, err
	}
	maxBackups, err := positiveEnvInt("MCP_GATEWAY_AUTH_AUDIT_MAX_BACKUPS", DefaultMaxBackups)
	if err != nil {
		return Config{}, err
	}
	maxAgeDays, err := positiveEnvInt("MCP_GATEWAY_AUTH_AUDIT_MAX_AGE_DAYS", DefaultMaxAgeDays)
	if err != nil {
		return Config{}, err
	}
	return Config{
		Path:            path,
		MaxSizeBytes:    int64(maxSizeMB) * 1024 * 1024,
		MaxBackups:      maxBackups,
		MaxAge:          time.Duration(maxAgeDays) * 24 * time.Hour,
		FailureCapacity: DefaultFailureLimit,
	}, nil
}

func positiveEnvInt(name string, fallback int) (int, error) {
	raw := strings.TrimSpace(os.Getenv(name))
	if raw == "" {
		return fallback, nil
	}
	value, err := strconv.Atoi(raw)
	if err != nil || value <= 0 {
		return 0, fmt.Errorf("%s must be a positive integer, got %q", name, raw)
	}
	return value, nil
}

// ResolvePath は Git worktree 外の絶対監査ログ path を返す。
func ResolvePath(configured string) (string, error) {
	path := configured
	if path == "" {
		var err error
		path, err = defaultPath(runtime.GOOS, os.Getenv, os.UserHomeDir)
		if err != nil {
			return "", err
		}
	}
	if !filepath.IsAbs(path) {
		return "", fmt.Errorf("auth audit log path must be absolute, got %q", path)
	}
	path = filepath.Clean(path)
	if err := rejectGitWorktreePath(path); err != nil {
		return "", err
	}
	return path, nil
}

func defaultPath(goos string, getenv func(string) string, userHomeDir func() (string, error)) (string, error) {
	switch goos {
	case "windows":
		base := strings.TrimSpace(getenv("LOCALAPPDATA"))
		if base == "" {
			return "", errors.New("cannot resolve auth audit log path: LOCALAPPDATA is not set")
		}
		return windowsJoin(base, "mcp-gateway", "logs", "auth-audit.jsonl"), nil
	case "darwin":
		home, err := userHomeDir()
		if err != nil || strings.TrimSpace(home) == "" {
			return "", fmt.Errorf("cannot resolve auth audit log path: user home directory unavailable: %w", err)
		}
		return path.Join(home, "Library", "Logs", "mcp-gateway", "auth-audit.jsonl"), nil
	default:
		base := strings.TrimSpace(getenv("XDG_STATE_HOME"))
		if base != "" {
			if !strings.HasPrefix(base, "/") {
				return "", fmt.Errorf("XDG_STATE_HOME must be absolute, got %q", base)
			}
			return path.Join(base, "mcp-gateway", "logs", "auth-audit.jsonl"), nil
		}
		home, err := userHomeDir()
		if err != nil || strings.TrimSpace(home) == "" {
			return "", fmt.Errorf("cannot resolve auth audit log path: XDG_STATE_HOME and user home directory are unavailable: %w", err)
		}
		return path.Join(home, ".local", "state", "mcp-gateway", "logs", "auth-audit.jsonl"), nil
	}
}

func windowsJoin(base string, elements ...string) string {
	result := strings.TrimRight(base, `\/`)
	for _, element := range elements {
		result += `\` + strings.Trim(element, `\/`)
	}
	return result
}

func rejectGitWorktreePath(path string) error {
	dir := filepath.Dir(path)
	for {
		if _, err := os.Stat(filepath.Join(dir, ".git")); err == nil {
			return fmt.Errorf("auth audit log path must be outside a Git worktree, got %q", path)
		} else if !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("checking auth audit log path %q: %w", path, err)
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return nil
		}
		dir = parent
	}
}

// FileRecorder はイベントを1行1 JSON で保存し、診断 API 向けに直近の失敗を
// 上限付きメモリ領域へ保持する。
type FileRecorder struct {
	mu sync.Mutex

	cfg  Config
	file *os.File
	size int64
	now  func() time.Time

	failures    []Event
	failureHead int
	failureLen  int
}

// New は監査ログを作成し、保存できない場合は fail closed でエラーを返す。
func New(cfg Config) (*FileRecorder, error) {
	return newRecorder(cfg, time.Now)
}

func newRecorder(cfg Config, now func() time.Time) (*FileRecorder, error) {
	if !filepath.IsAbs(cfg.Path) {
		return nil, fmt.Errorf("auth audit log path must be absolute, got %q", cfg.Path)
	}
	if cfg.MaxSizeBytes <= 0 {
		return nil, errors.New("auth audit max size must be positive")
	}
	if cfg.MaxBackups <= 0 {
		return nil, errors.New("auth audit max backups must be positive")
	}
	if cfg.MaxAge <= 0 {
		return nil, errors.New("auth audit max age must be positive")
	}
	if cfg.FailureCapacity <= 0 {
		return nil, errors.New("auth audit failure capacity must be positive")
	}
	if err := rejectGitWorktreePath(cfg.Path); err != nil {
		return nil, err
	}

	dir := filepath.Dir(cfg.Path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("creating auth audit log directory %q: %w", dir, err)
	}
	resolvedDir, err := filepath.EvalSymlinks(dir)
	if err != nil {
		return nil, fmt.Errorf("resolving auth audit log directory %q: %w", dir, err)
	}
	resolvedPath := filepath.Join(resolvedDir, filepath.Base(cfg.Path))
	if err := rejectGitWorktreePath(resolvedPath); err != nil {
		return nil, err
	}
	if _, err := os.Lstat(resolvedPath); err == nil {
		resolvedFile, err := filepath.EvalSymlinks(resolvedPath)
		if err != nil {
			return nil, fmt.Errorf("resolving auth audit log file %q: %w", resolvedPath, err)
		}
		if err := rejectGitWorktreePath(resolvedFile); err != nil {
			return nil, err
		}
		resolvedPath = resolvedFile
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("checking auth audit log file %q: %w", resolvedPath, err)
	}
	cfg.Path = resolvedPath

	file, err := os.OpenFile(cfg.Path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, fmt.Errorf("opening auth audit log %q: %w", cfg.Path, err)
	}
	if err := file.Chmod(0o600); err != nil {
		_ = file.Close()
		return nil, fmt.Errorf("setting auth audit log permissions %q: %w", cfg.Path, err)
	}
	info, err := file.Stat()
	if err != nil {
		_ = file.Close()
		return nil, fmt.Errorf("reading auth audit log metadata %q: %w", cfg.Path, err)
	}

	recorder := &FileRecorder{
		cfg:      cfg,
		file:     file,
		size:     info.Size(),
		now:      now,
		failures: make([]Event, cfg.FailureCapacity),
	}
	if err := recorder.cleanupLocked(); err != nil {
		_ = file.Close()
		return nil, err
	}
	return recorder, nil
}

func (r *FileRecorder) Path() string {
	return r.cfg.Path
}

func (r *FileRecorder) Record(event Event) error {
	now := r.now().UTC()
	if event.Timestamp.IsZero() {
		event.Timestamp = now
	} else {
		event.Timestamp = event.Timestamp.UTC()
	}
	event.Event = auditEventName

	line, err := json.Marshal(event)
	if err != nil {
		return fmt.Errorf("encoding auth audit event: %w", err)
	}
	line = append(line, '\n')

	r.mu.Lock()
	if r.file == nil {
		r.mu.Unlock()
		return errors.New("auth audit recorder is closed")
	}
	if r.size > 0 && r.size+int64(len(line)) > r.cfg.MaxSizeBytes {
		if err := r.rotateLocked(now); err != nil {
			r.mu.Unlock()
			return err
		}
	}
	n, err := r.file.Write(line)
	if err == nil && n != len(line) {
		err = io.ErrShortWrite
	}
	if err != nil {
		r.mu.Unlock()
		return fmt.Errorf("writing auth audit log %q: %w", r.cfg.Path, err)
	}
	r.size += int64(n)
	if event.Result == "failure" {
		r.addFailureLocked(event)
	}
	r.mu.Unlock()

	attrs := []any{
		"timestamp", event.Timestamp.Format(time.RFC3339Nano),
		"event", event.Event,
		"phase", event.Phase,
		"provider", event.Provider,
		"result", event.Result,
		"message", event.Message,
	}
	if event.ErrorClass != "" {
		attrs = append(attrs, "error_class", event.ErrorClass)
	}
	if event.OAuthError != "" {
		attrs = append(attrs, "oauth_error", event.OAuthError)
	}
	if event.HTTPStatus != 0 {
		attrs = append(attrs, "http_status", event.HTTPStatus)
	}
	if event.TokenHash != "" {
		attrs = append(attrs, "token_hash", event.TokenHash)
	}
	if event.Result == "failure" {
		slog.Warn("oauth audit", attrs...)
	} else {
		slog.Info("oauth audit", attrs...)
	}
	return nil
}

func (r *FileRecorder) addFailureLocked(event Event) {
	if r.failureLen < len(r.failures) {
		index := (r.failureHead + r.failureLen) % len(r.failures)
		r.failures[index] = event
		r.failureLen++
		return
	}
	r.failures[r.failureHead] = event
	r.failureHead = (r.failureHead + 1) % len(r.failures)
}

// RecentFailures は診断表示向けに最新順の snapshot を返す。
func (r *FileRecorder) RecentFailures() []Event {
	r.mu.Lock()
	defer r.mu.Unlock()

	out := make([]Event, 0, r.failureLen)
	for offset := r.failureLen - 1; offset >= 0; offset-- {
		index := (r.failureHead + offset) % len(r.failures)
		out = append(out, r.failures[index])
	}
	return out
}

func (r *FileRecorder) rotateLocked(now time.Time) error {
	if err := r.file.Close(); err != nil {
		return fmt.Errorf("closing auth audit log before rotation: %w", err)
	}
	r.file = nil

	rotated, err := r.nextRotatedPathLocked(now)
	if err != nil {
		return err
	}
	if err := os.Rename(r.cfg.Path, rotated); err != nil {
		return fmt.Errorf("rotating auth audit log %q to %q: %w", r.cfg.Path, rotated, err)
	}

	file, err := os.OpenFile(r.cfg.Path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return fmt.Errorf("opening new auth audit log %q after rotation: %w", r.cfg.Path, err)
	}
	if err := file.Chmod(0o600); err != nil {
		_ = file.Close()
		return fmt.Errorf("setting new auth audit log permissions %q: %w", r.cfg.Path, err)
	}
	r.file = file
	r.size = 0
	return r.cleanupLocked()
}

func (r *FileRecorder) nextRotatedPathLocked(now time.Time) (string, error) {
	ext := filepath.Ext(r.cfg.Path)
	stem := strings.TrimSuffix(r.cfg.Path, ext)
	timestamp := now.UTC().Format("20060102T150405.000000000Z")
	for sequence := 0; sequence < 1000; sequence++ {
		candidate := fmt.Sprintf("%s.%s.%03d%s", stem, timestamp, sequence, ext)
		if _, err := os.Stat(candidate); errors.Is(err, os.ErrNotExist) {
			return candidate, nil
		} else if err != nil {
			return "", fmt.Errorf("checking rotated auth audit log %q: %w", candidate, err)
		}
	}
	return "", errors.New("could not allocate a unique auth audit rotation filename")
}

func (r *FileRecorder) cleanupLocked() error {
	files, err := r.rotatedFilesLocked()
	if err != nil {
		return err
	}
	cutoff := r.now().Add(-r.cfg.MaxAge)
	kept := make([]rotatedFile, 0, len(files))
	for _, file := range files {
		if file.modTime.Before(cutoff) {
			if err := os.Remove(file.path); err != nil && !errors.Is(err, os.ErrNotExist) {
				return fmt.Errorf("removing expired auth audit log %q: %w", file.path, err)
			}
			continue
		}
		kept = append(kept, file)
	}
	for index := r.cfg.MaxBackups; index < len(kept); index++ {
		if err := os.Remove(kept[index].path); err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("removing excess auth audit log %q: %w", kept[index].path, err)
		}
	}
	return nil
}

type rotatedFile struct {
	path    string
	modTime time.Time
}

func (r *FileRecorder) rotatedFilesLocked() ([]rotatedFile, error) {
	ext := filepath.Ext(r.cfg.Path)
	stem := strings.TrimSuffix(r.cfg.Path, ext)
	paths, err := filepath.Glob(stem + ".*" + ext)
	if err != nil {
		return nil, fmt.Errorf("listing rotated auth audit logs: %w", err)
	}
	files := make([]rotatedFile, 0, len(paths))
	for _, path := range paths {
		info, err := os.Stat(path)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("reading rotated auth audit log metadata %q: %w", path, err)
		}
		files = append(files, rotatedFile{path: path, modTime: info.ModTime()})
	}
	slices.SortFunc(files, func(a, b rotatedFile) int {
		return b.modTime.Compare(a.modTime)
	})
	return files, nil
}

func (r *FileRecorder) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.file == nil {
		return nil
	}
	err := r.file.Close()
	r.file = nil
	if err != nil {
		return fmt.Errorf("closing auth audit log %q: %w", r.cfg.Path, err)
	}
	return nil
}
