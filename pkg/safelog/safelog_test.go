package safelog

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

func capture(level Level, f func(*Logger)) string {
	var buf bytes.Buffer
	f(New(&buf, level))
	return buf.String()
}

// The central property: a fingerprint is truncated before it reaches a log line.
// A full SHA-256 is harmless, but the habit of logging full digests is how a
// full DER blob eventually ends up in a log line.
func TestFingerprintIsTruncated(t *testing.T) {
	full := strings.Repeat("ab", 32) // 64 hex chars
	out := capture(LevelInfo, func(l *Logger) {
		l.Info("observed", Fingerprint("sha256", full))
	})
	if strings.Contains(out, full) {
		t.Fatal("the full fingerprint reached the log line")
	}
	if !strings.Contains(out, full[:16]) {
		t.Fatalf("the truncated prefix is missing: %s", out)
	}
	if !strings.Contains(out, "...") {
		t.Fatalf("truncation is not marked, so a reader cannot tell it was shortened: %s", out)
	}
}

func TestFingerprintHandlesShortAndMessyInput(t *testing.T) {
	for _, in := range []string{"", "abc", "  ABCDEF  ", strings.Repeat("f", 200)} {
		out := capture(LevelInfo, func(l *Logger) { l.Info("m", Fingerprint("fp", in)) })
		if out == "" {
			t.Fatalf("no output for input %q", in)
		}
	}
}

// Levels must actually filter. "Debug mode dumped the buffer" is the classic
// way the key invariant dies, so debug output must be genuinely suppressed at
// higher levels rather than merely discouraged.
func TestLevelFiltering(t *testing.T) {
	out := capture(LevelInfo, func(l *Logger) { l.Debug("secret-ish detail") })
	if strings.Contains(out, "secret-ish") {
		t.Fatal("a debug line was emitted at info level")
	}
	out = capture(LevelDebug, func(l *Logger) { l.Debug("visible detail") })
	if !strings.Contains(out, "visible detail") {
		t.Fatal("a debug line was suppressed at debug level")
	}
	out = capture(LevelError, func(l *Logger) {
		l.Debug("d")
		l.Info("i")
		l.Warn("w")
		l.Error("e")
	})
	for _, absent := range []string{`"msg":"d"`, `"msg":"i"`, `"msg":"w"`} {
		if strings.Contains(out, absent) {
			t.Fatalf("level filtering leaked %s at error level", absent)
		}
	}
	if !strings.Contains(out, `"msg":"e"`) {
		t.Fatal("error level suppressed an error")
	}
}

func TestOutputIsStructuredJSON(t *testing.T) {
	out := capture(LevelInfo, func(l *Logger) {
		l.Info("scan complete",
			Int("files_seen", 9),
			Str("phase", "filesystem"),
			Bool("dry_run", true),
			Dur("elapsed", 1500*time.Millisecond),
		)
	})
	var m map[string]any
	if err := json.Unmarshal([]byte(strings.TrimSpace(out)), &m); err != nil {
		t.Fatalf("output is not valid JSON: %v\n%s", err, out)
	}
	if m["msg"] != "scan complete" || m["files_seen"] != float64(9) {
		t.Fatalf("fields missing from output: %v", m)
	}
}

// Err logs an error's message. An error carrying key material would be a bug at
// its CONSTRUCTION site, not here — but assert the boundary is at least narrow:
// only the string form is taken, never a wrapped value.
func TestErrLogsOnlyTheMessage(t *testing.T) {
	out := capture(LevelError, func(l *Logger) { l.Error("failed", Err(errors.New("dial timeout"))) })
	if !strings.Contains(out, "dial timeout") {
		t.Fatalf("error message missing: %s", out)
	}
	out = capture(LevelError, func(l *Logger) { l.Error("failed", Err(nil)) })
	if !strings.Contains(out, "<nil>") {
		t.Fatalf("nil error not handled: %s", out)
	}
}

func TestParseLevel(t *testing.T) {
	cases := map[string]Level{
		"debug": LevelDebug, "DEBUG": LevelDebug, " info ": LevelInfo, "": LevelInfo,
		"warn": LevelWarn, "warning": LevelWarn, "error": LevelError,
	}
	for in, want := range cases {
		got, ok := ParseLevel(in)
		if !ok || got != want {
			t.Errorf("ParseLevel(%q) = %v,%v want %v,true", in, got, ok, want)
		}
	}
	if _, ok := ParseLevel("verbose"); ok {
		t.Error("ParseLevel accepted an unknown level instead of reporting it")
	}
}

func TestDiscardAndNilAreSafe(t *testing.T) {
	Discard().Info("nothing")
	var l *Logger
	l.Info("must not panic on a nil logger")
}

// A compile-time property, asserted here in prose because it cannot be asserted
// in code: NO function in this package accepts `any`, `interface{}`, or a
// []byte. A caller holding certificate DER has nothing to pass it to.
//
// If a future change adds such a parameter, this comment is the place the
// reviewer should object. The import check (CI-008) then has nothing left to
// protect, because the boundary would have moved from the type system back into
// a lint rule.
func TestFieldConstructorsAreTypedOnly(t *testing.T) {
	// Exercising every constructor documents the complete surface.
	fields := []Field{
		Str("a", "b"), Int("c", 1), Int64("d", 2), Bool("e", true),
		Dur("f", time.Second), Time("g", time.Now()), Err(errors.New("h")),
		Path("i", "/tmp/x"), Fingerprint("j", "abcd"),
	}
	if len(fields) != 9 {
		t.Fatalf("the constructor surface changed; re-read the doc comment above")
	}
}
