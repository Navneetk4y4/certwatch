// Package safelog is the only logging path in the collector.
//
// # Why a package instead of a lint rule
//
// INV-3 says no log line, at any verbosity including debug, may contain more
// than the first 8 bytes of any DER blob or any PEM body line. The obvious
// enforcement is a static check for []byte at log call sites — but that check
// needs full type information to be accurate, and an approximate security
// control is a security control that will be wrong on the day it matters.
//
// So the boundary is structural instead: this API cannot accept a []byte.
// There is no Any, no interface{}, no variadic ...any. A caller holding
// certificate DER cannot pass it to a log call, because no function here has a
// parameter it would fit. "Debug mode dumped the buffer" — the classic way this
// invariant dies — is not a mistake that can be made.
//
// The import check (internal/tools/importcheck) then enforces one simple,
// accurate, purely syntactic rule: nothing outside this package imports log,
// log/slog, or uses fmt print functions.
//
// # Fingerprints
//
// Certificate fingerprints ARE safe to log and are often the only useful
// identifier. Fingerprint() truncates to 16 hex characters, which is ample for
// correlation and cannot reconstruct anything.
package safelog

import (
	"io"
	"log/slog"
	"os"
	"strings"
	"time"
)

// Field is a log attribute. It can only be constructed by the typed
// constructors below, so no caller can smuggle a byte slice into one.
type Field struct {
	key string
	val slog.Value
}

func Str(k, v string) Field               { return Field{k, slog.StringValue(v)} }
func Int(k string, v int) Field           { return Field{k, slog.IntValue(v)} }
func Int64(k string, v int64) Field       { return Field{k, slog.Int64Value(v)} }
func Bool(k string, v bool) Field         { return Field{k, slog.BoolValue(v)} }
func Dur(k string, v time.Duration) Field { return Field{k, slog.DurationValue(v)} }
func Time(k string, v time.Time) Field    { return Field{k, slog.TimeValue(v.UTC())} }

// Err logs an error's message. Errors are formatted strings, not buffers; an
// error carrying key material would be a bug at its construction site, not here.
func Err(err error) Field {
	if err == nil {
		return Field{"error", slog.StringValue("<nil>")}
	}
	return Field{"error", slog.StringValue(err.Error())}
}

// Path logs a filesystem path. Paths are sensitive (internal hostnames, layout)
// but not secret, and a scanner that cannot say which file it skipped is useless.
func Path(k, v string) Field { return Field{k, slog.StringValue(v)} }

// Fingerprint logs a certificate fingerprint, truncated to 16 hex characters.
// Full DER never reaches a log line; a truncated fingerprint is enough to
// correlate two observations and not enough to reconstruct anything.
func Fingerprint(k, hexDigest string) Field {
	d := strings.ToLower(strings.TrimSpace(hexDigest))
	if len(d) > 16 {
		d = d[:16] + "..."
	}
	return Field{k, slog.StringValue(d)}
}

// Level is safelog's own level type.
//
// It exists so that a caller never has to import log/slog to name a level.
// Without it, every call site would import the package the boundary bans, and
// the import check would be unenforceable — the boundary would exist on paper
// and not in the build.
type Level int

const (
	LevelDebug Level = iota
	LevelInfo
	LevelWarn
	LevelError
)

func (l Level) String() string {
	switch l {
	case LevelDebug:
		return "DEBUG"
	case LevelWarn:
		return "WARN"
	case LevelError:
		return "ERROR"
	default:
		return "INFO"
	}
}

func (l Level) slog() slog.Level {
	switch l {
	case LevelDebug:
		return slog.LevelDebug
	case LevelWarn:
		return slog.LevelWarn
	case LevelError:
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}

// ParseLevel maps a --log-level flag value to a Level.
func ParseLevel(s string) (Level, bool) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "debug":
		return LevelDebug, true
	case "info", "":
		return LevelInfo, true
	case "warn", "warning":
		return LevelWarn, true
	case "error":
		return LevelError, true
	}
	return LevelInfo, false
}

// Logger is deliberately narrow. Four levels, a message, and typed fields.
type Logger struct {
	inner *slog.Logger
	level *slog.LevelVar
}

// New returns a Logger writing structured JSON to w.
func New(w io.Writer, level Level) *Logger {
	lv := new(slog.LevelVar)
	lv.Set(level.slog())
	return &Logger{
		inner: slog.New(slog.NewJSONHandler(w, &slog.HandlerOptions{Level: lv})),
		level: lv,
	}
}

// NewStderr is the default for command-line use.
func NewStderr(level Level) *Logger { return New(os.Stderr, level) }

// Discard is for tests and for --quiet.
func Discard() *Logger { return New(io.Discard, LevelError) }

func (l *Logger) SetLevel(v Level) { l.level.Set(v.slog()) }

func (l *Logger) Debug(msg string, f ...Field) { l.log(slog.LevelDebug, msg, f) }
func (l *Logger) Info(msg string, f ...Field)  { l.log(slog.LevelInfo, msg, f) }
func (l *Logger) Warn(msg string, f ...Field)  { l.log(slog.LevelWarn, msg, f) }
func (l *Logger) Error(msg string, f ...Field) { l.log(slog.LevelError, msg, f) }

func (l *Logger) log(lv slog.Level, msg string, fields []Field) {
	if l == nil || l.inner == nil {
		return
	}
	attrs := make([]slog.Attr, 0, len(fields))
	for _, f := range fields {
		attrs = append(attrs, slog.Attr{Key: f.key, Value: f.val})
	}
	l.inner.LogAttrs(nil, lv, msg, attrs...)
}
