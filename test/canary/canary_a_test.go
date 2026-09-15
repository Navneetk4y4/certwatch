package canary_test

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/certwatch/certwatch/pkg/safeio"
	"github.com/certwatch/certwatch/pkg/safelog"
	"github.com/certwatch/certwatch/test/canary"
)

const seedPath = "testdata/seed.bin"

// expectedSkips is the exact multiset the five planted forms must produce.
// Asserting the multiset — not just a count — proves each protection path was
// actually exercised rather than the files having been missed entirely.
var expectedSkips = map[safeio.Classification]int{
	safeio.SkippedForbiddenExtension: 2, // server.key, id_rsa
	safeio.SkippedPrivateKeyBlock:    2, // raw.der (file), bundle.pem (block)
	safeio.SkippedSymlinkEscape:      1, // link.pem
}

// TestCanaryA is the security canary, part one: the filesystem surface.
//
// It runs the scan at default AND debug verbosity, captures every artefact that
// exists at this point in the build, and fails on any trace of the planted key.
//
// This is the single most important test in the project. If only one test from
// the whole strategy survives, it is this one.
func TestCanaryA(t *testing.T) {
	for _, mode := range []struct {
		name  string
		level safelog.Level
	}{
		{"default", safelog.LevelInfo},
		{"debug", safelog.LevelDebug}, // "debug mode dumped the buffer" is how this invariant dies
	} {
		t.Run(mode.name, func(t *testing.T) {
			runCanaryA(t, mode.level)
		})
	}
}

func runCanaryA(t *testing.T, level safelog.Level) {
	t.Helper()
	root := t.TempDir()

	tree, err := canary.Plant(root, seedPath)
	if err != nil {
		t.Fatalf("planting the fixture tree: %v", err)
	}
	t.Logf("planted %d forms of the key and %d valid certificates", len(tree.Forms), len(tree.Certificates))

	// Capture every surface that exists at this point in the build order.
	var stdout, stderr, logBuf bytes.Buffer
	logger := safelog.New(&logBuf, level)

	logger.Debug("canary scan starting",
		safelog.Path("root", tree.ScanDir),
		safelog.Int("planted_forms", len(tree.Forms)))

	policy, err := safeio.NewPolicy([]string{tree.ScanDir}, safeio.PolicyOptions{})
	if err != nil {
		t.Fatalf("building policy: %v", err)
	}

	results, counters, err := safeio.ReadCertificatesOnly(context.Background(), tree.ScanDir, policy)
	if err != nil {
		t.Fatalf("scan failed: %v", err)
	}

	// Emit everything a real run would emit, at the requested verbosity. If any
	// of this code path stringifies a buffer, the detector below will find it.
	for _, r := range results {
		logger.Debug("file classified",
			safelog.Path("path", r.Path),
			safelog.Str("class", r.Class.String()),
			safelog.Str("reason", r.Reason),
			safelog.Int("der_blocks", len(r.CertificateDER)))
		fmt.Fprintf(&stdout, "%s\t%s\t%s\n", r.Path, r.Class, r.Reason)
	}
	for _, line := range counters.Summary() {
		fmt.Fprintln(&stdout, line)
	}
	logger.Info("canary scan complete",
		safelog.Int("files_seen", counters.FilesSeen),
		safelog.Int("certificates", counters.CertificatesReturned),
		safelog.Int("skips", counters.TotalSkips()))

	// The returned results are themselves an artefact: if DER carrying key
	// material were returned to the caller, that is a leak into the program.
	var returned bytes.Buffer
	for _, r := range results {
		for _, der := range r.CertificateDER {
			returned.Write(der)
		}
	}

	// On-disk state that a real run would produce. No spool exists yet; when it
	// does (build item 116) CANARY-B adds it here.
	spoolBytes := readDirBytes(t, filepath.Join(root, "spool"))

	artefacts := []canary.Artefact{
		{Name: "returned-certificate-der", Data: returned.Bytes()},
		{Name: "stdout", Data: stdout.Bytes()},
		{Name: "stderr", Data: stderr.Bytes()},
		{Name: "log-output", Data: logBuf.Bytes()},
		{Name: "spool-directory", Data: spoolBytes},
	}

	// ---- ASSERTION 1: zero key bytes, in any artefact. ----
	if leaks := canary.Detect(tree.Key, artefacts); len(leaks) > 0 {
		for _, l := range leaks {
			t.Errorf("PRIVATE KEY LEAK: %s", l)
		}
		t.Fatalf("INV-1 VIOLATED: %d leak(s) detected at log level %v.\n"+
			"Private-key material must never leave the collector. This is not a style issue.", len(leaks), level)
	}

	// ---- ASSERTION 2: the scanner actually worked. ----
	// A scanner that reads nothing trivially passes a leak test. The canary must
	// prove the scanner works AND does not leak, not just the second half.
	if counters.CertificatesReturned < 3 {
		t.Fatalf("only %d certificates reported, want >= 3.\n"+
			"A scanner that refuses everything passes a leak test trivially and is useless.",
			counters.CertificatesReturned)
	}

	// ---- ASSERTION 3: every protection path was exercised. ----
	got := counters.SkipMultiset()
	for class, want := range expectedSkips {
		if got[class] != want {
			t.Errorf("skip class %v = %d, want %d", class, got[class], want)
		}
	}
	if total := counters.TotalSkips(); total != 5 {
		t.Errorf("TotalSkips = %d, want exactly 5 (one per planted form): %v", total, got)
	}
	for class, n := range got {
		if _, expected := expectedSkips[class]; !expected && n > 0 {
			t.Errorf("unexpected skip class %v (%d); the fixture tree should produce only the five planted forms", class, n)
		}
	}

	// ---- ASSERTION 4: counters reconcile. ----
	if ok, why := counters.Conserved(); !ok {
		t.Fatalf("counter conservation violated: %s", why)
	}

	// ---- Result marker. A test that silently does not run is a failed test. ----
	t.Logf("CANARY-A-RESULT level=%v files=%d certificates=%d skips=%d leaks=0",
		level, counters.FilesSeen, counters.CertificatesReturned, counters.TotalSkips())
}

// TestCanaryDetectorDetects proves the detector is not vacuous.
//
// A leak detector that cannot detect a leak passes every test and protects
// nothing. This plants the key directly into each artefact and asserts every
// detection mode fires.
func TestCanaryDetectorDetects(t *testing.T) {
	pk, err := canary.GenerateKey(seedPath)
	if err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name string
		data []byte
	}{
		{"raw modulus", pk.ModulusRaw},
		{"raw pkcs8 der", pk.PKCS8DER},
		{"raw pkcs1 der", pk.PKCS1DER},
		{"32-byte window of the modulus", pk.ModulusRaw[40:72]},
		{"modulus embedded in surrounding noise",
			append(append([]byte("log line prefix: "), pk.ModulusRaw[10:60]...), []byte(" suffix")...)},
		{"base64 of the pkcs8 der", []byte(b64(pk.PKCS8DER))},
		{"base64 of a 48-byte window", []byte(b64(pk.PKCS8DER[7:120]))},
		{"a single PEM body line", []byte(pk.PEMBodies[1])},
		{"PEM body line inside JSON", []byte(`{"data":"` + pk.PEMBodies[2] + `"}`)},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			leaks := canary.Detect(pk, []canary.Artefact{{Name: "planted", Data: tc.data}})
			if len(leaks) == 0 {
				t.Fatalf("detector missed a deliberate leak of %d bytes (%s).\n"+
					"A detector that cannot detect a leak protects nothing.", len(tc.data), tc.name)
			}
		})
	}

	// And the converse: it must not fire on innocent content, or it will be
	// disabled by whoever gets tired of false positives.
	innocent := []canary.Artefact{
		{Name: "certificate", Data: bytes.Repeat([]byte{0x30, 0x82, 0x01, 0x22}, 500)},
		{Name: "log", Data: []byte(`{"level":"INFO","msg":"scan complete","files_seen":9}`)},
		{Name: "empty", Data: nil},
		{Name: "text", Data: []byte("the quick brown fox jumps over the lazy dog, repeatedly and at length")},
	}
	if leaks := canary.Detect(pk, innocent); len(leaks) > 0 {
		t.Fatalf("false positive on innocent content: %v", leaks)
	}
}

func b64(b []byte) string {
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
	_ = alphabet
	return encodeStd(b)
}

func readDirBytes(t *testing.T, dir string) []byte {
	t.Helper()
	var buf bytes.Buffer
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil // no spool yet; CANARY-B adds it at build item 090
	}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		b, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			continue
		}
		buf.Write(b)
	}
	return buf.Bytes()
}
