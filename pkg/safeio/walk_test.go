package safeio

import (
	"bytes"
	"context"
	"crypto/x509"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

func walkDir(t *testing.T, dir string, opt PolicyOptions) ([]Result, *Counters) {
	t.Helper()
	p := mustPolicy(t, dir, opt)
	res, c, err := ReadCertificatesOnly(context.Background(), p.Roots()[0], p)
	if err != nil {
		t.Fatalf("ReadCertificatesOnly: %v", err)
	}
	if ok, why := c.Conserved(); !ok {
		t.Fatalf("counter conservation violated: %s", why)
	}
	return res, c
}

func countClass(c *Counters, class Classification) int { return c.Dispositions[class] }

// SAFEIO-002 + REGRESSION: a subtree deeper than the limit is PRUNED, and the
// rest of the tree is still searched.
//
// The earlier implementation aborted the entire walk here. Because entries are
// name-sorted, anyone able to create a directory under a scanned root could
// suppress discovery of every certificate in it with one alphabetically-early
// deep chain — `mkdir -p a/b/c/d/e/f/g/h/i` in a writable upload directory was
// the whole exploit. Found by adversarial review, confirmed with this scenario.
func TestWalkDepthLimitPrunesRatherThanAborting(t *testing.T) {
	dir := t.TempDir()

	// An alphabetically-EARLY deep chain containing nothing of value.
	deep := filepath.Join(dir, "aaa")
	for i := 0; i < 12; i++ {
		deep = filepath.Join(deep, fmt.Sprintf("d%02d", i))
	}
	if err := os.MkdirAll(deep, 0o755); err != nil {
		t.Fatal(err)
	}
	// An ordinary certificate, alphabetically later, at depth 1.
	writeFile(t, filepath.Join(dir, "zzz", "real.pem"),
		pemBlock("CERTIFICATE", testCertDER(t, "survivor.example")))

	_, c := walkDir(t, dir, PolicyOptions{MaxDepth: 4})

	if c.CertificatesReturned != 1 {
		t.Fatalf("CertificatesReturned = %d, want 1. A deep directory suppressed discovery of a "+
			"certificate elsewhere in the tree: %v truncated=%v why=%q",
			c.CertificatesReturned, c.Dispositions, c.Truncated, c.TruncatedWhy)
	}
	if c.Truncated {
		t.Fatalf("the walk reported global truncation for a local depth limit: %q", c.TruncatedWhy)
	}
	if c.PrunedSubtrees == 0 {
		t.Fatal("the pruned subtree was not counted; the coverage gap would be invisible")
	}
	if countClass(c, SkippedDepthExceeded) == 0 {
		t.Fatalf("no SkippedDepthExceeded disposition emitted: %v", c.Dispositions)
	}
}

// Pruning must still be VISIBLE. A local coverage gap that nobody can see is
// the same failure as a silent one.
func TestPrunedSubtreeIsReported(t *testing.T) {
	dir := t.TempDir()
	deep := dir
	for i := 0; i < 10; i++ {
		deep = filepath.Join(deep, fmt.Sprintf("d%02d", i))
	}
	if err := os.MkdirAll(deep, 0o755); err != nil {
		t.Fatal(err)
	}
	res, c := walkDir(t, dir, PolicyOptions{MaxDepth: 3})
	found := false
	for _, r := range res {
		if r.Class == SkippedDepthExceeded && r.Reason != "" {
			found = true
		}
	}
	if !found {
		t.Fatal("no result row explains which subtree was not searched")
	}
	if len(c.Summary()) == 0 {
		t.Fatal("the skip summary does not mention the pruned subtree")
	}
}

// SAFEIO-002: the file-count budget stops the walk and is reported.
func TestWalkFileCountLimit(t *testing.T) {
	dir := t.TempDir()
	der := testCertDER(t, "many.example")
	for i := 0; i < 60; i++ {
		writeFile(t, filepath.Join(dir, fmt.Sprintf("c%03d.pem", i)), pemBlock("CERTIFICATE", der))
	}
	_, c := walkDir(t, dir, PolicyOptions{MaxFiles: 10})
	if !c.Truncated {
		t.Fatal("expected truncation at the file limit")
	}
	if c.FilesSeen > 10 {
		t.Fatalf("walk saw %d files past a limit of 10", c.FilesSeen)
	}
}

// REGRESSION: the file budget must bound SKIPPED files too.
//
// The check used to live inside visitFile, after the extension gate had already
// rejected the entry — so a directory of thousands of .p12 files ran clean past
// MaxFiles, because a skipped file never reached the check. Found by
// adversarial review.
func TestFileBudgetBoundsSkipsToo(t *testing.T) {
	dir := t.TempDir()
	for i := 0; i < 200; i++ {
		writeFile(t, filepath.Join(dir, fmt.Sprintf("store%03d.p12", i)), []byte("binary"))
	}
	_, c := walkDir(t, dir, PolicyOptions{MaxFiles: 5})
	if c.FilesSeen > 5 {
		t.Fatalf("FilesSeen = %d with MaxFiles=5; skipped files escaped the budget", c.FilesSeen)
	}
	if !c.Truncated {
		t.Fatal("hitting the file budget was not reported")
	}
}

// SAFEIO-002: irregular files are refused by type, before any open. A FIFO that
// was opened for reading would block the walk forever.
func TestWalkRefusesIrregularFiles(t *testing.T) {
	dir := t.TempDir()
	fifo := filepath.Join(dir, "pipe.pem")
	if err := syscall.Mkfifo(fifo, 0o644); err != nil {
		t.Skipf("mkfifo unavailable: %v", err)
	}
	writeFile(t, filepath.Join(dir, "real.pem"), pemBlock("CERTIFICATE", testCertDER(t, "real.example")))

	done := make(chan struct{})
	var c *Counters
	go func() {
		_, c = walkDir(t, dir, PolicyOptions{})
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("walk blocked on a FIFO")
	}
	if countClass(c, SkippedIrregularFile) != 1 {
		t.Fatalf("FIFO not refused: %v", c.Dispositions)
	}
	if c.CertificatesReturned != 1 {
		t.Fatalf("the real certificate was not read: %d", c.CertificatesReturned)
	}
}

func TestWalkRefusesUnixSocket(t *testing.T) {
	dir := t.TempDir()
	sock := filepath.Join(dir, "s.pem")
	l, err := netListenUnix(sock)
	if err != nil {
		t.Skipf("unix socket unavailable: %v", err)
	}
	defer l()
	_, c := walkDir(t, dir, PolicyOptions{})
	if countClass(c, SkippedIrregularFile) != 1 {
		t.Fatalf("unix socket not refused: %v", c.Dispositions)
	}
}

// SAFEIO-004: a symlink is never followed, including one pointing at a key.
func TestWalkNeverFollowsSymlinks(t *testing.T) {
	base := t.TempDir()
	scan := filepath.Join(base, "certs")
	secret := filepath.Join(base, "secret")
	key := testRSAKey(t)
	keyPEM := pemBlock("PRIVATE KEY", mustPKCS8(t, key))
	writeFile(t, filepath.Join(secret, "server.key"), keyPEM)
	writeFile(t, filepath.Join(scan, "good.pem"), pemBlock("CERTIFICATE", testCertDER(t, "good.example")))

	if err := os.Symlink(filepath.Join(secret, "server.key"), filepath.Join(scan, "link.pem")); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	// A symlink to a perfectly valid certificate is also refused: there is no
	// exception for "safe" links, because the exception is the vulnerability.
	if err := os.Symlink(filepath.Join(scan, "good.pem"), filepath.Join(scan, "alias.pem")); err != nil {
		t.Fatal(err)
	}

	res, c := walkDir(t, scan, PolicyOptions{})
	if got := countClass(c, SkippedSymlinkEscape); got != 2 {
		t.Fatalf("SkippedSymlinkEscape = %d, want 2: %v", got, c.Dispositions)
	}
	for _, r := range res {
		if r.Class.IsCertificate() {
			for _, der := range r.CertificateDER {
				if bytes.Contains(der, key.N.Bytes()[:32]) {
					t.Fatal("key material returned through a symlink")
				}
			}
		}
	}
	if c.CertificatesReturned != 1 {
		t.Fatalf("expected exactly the one real certificate, got %d", c.CertificatesReturned)
	}
}

// SAFEIO-004: the TOCTOU closure. A file is swapped for a symlink between the
// directory listing and the open. O_NOFOLLOW must refuse it every time.
func TestWalkTOCTOURace(t *testing.T) {
	if testing.Short() {
		t.Skip("race test skipped in -short")
	}
	base := t.TempDir()
	scan := filepath.Join(base, "certs")
	secret := filepath.Join(base, "secret")
	key := testRSAKey(t)
	writeFile(t, filepath.Join(secret, "server.key"), pemBlock("PRIVATE KEY", mustPKCS8(t, key)))
	target := filepath.Join(scan, "swap.pem")
	writeFile(t, target, pemBlock("CERTIFICATE", testCertDER(t, "swap.example")))

	if err := os.Symlink(filepath.Join(secret, "server.key"), filepath.Join(base, "evil")); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}

	var stop atomic.Bool
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for !stop.Load() {
			_ = os.Remove(target)
			_ = os.Symlink(filepath.Join(secret, "server.key"), target)
			_ = os.Remove(target)
			_ = os.WriteFile(target, pemBlock("CERTIFICATE", testCertDER(t, "swap.example")), 0o644)
		}
	}()

	keyPrefix := key.N.Bytes()[:32]
	p := mustPolicy(t, scan, PolicyOptions{})
	sawSymlinkRefusal := 0
	sawCertificate := 0
	for i := 0; i < 1000; i++ {
		res, c, err := ReadCertificatesOnly(context.Background(), p.Roots()[0], p)
		if err != nil {
			continue
		}
		sawSymlinkRefusal += c.Dispositions[SkippedSymlinkEscape]
		sawCertificate += c.CertificatesReturned
		for _, r := range res {
			for _, der := range r.CertificateDER {
				if bytes.Contains(der, keyPrefix) {
					stop.Store(true)
					wg.Wait()
					t.Fatalf("iteration %d: key material returned via a swapped symlink", i)
				}
			}
		}
	}
	stop.Store(true)
	wg.Wait()

	// A race test that never hits the race passes trivially and proves nothing.
	// Assert that both interleavings were actually observed: the swapper won at
	// least once (a symlink was refused) and lost at least once (a certificate
	// was read). Without this the test is decoration.
	if sawSymlinkRefusal == 0 {
		t.Fatal("the swap never won the race; O_NOFOLLOW was never exercised, so this test proved nothing")
	}
	if sawCertificate == 0 {
		t.Fatal("the swap always won; the scanner never read the real certificate, so a refusal proves nothing")
	}
	t.Logf("race exercised: %d symlink refusals, %d certificates read across 1000 iterations",
		sawSymlinkRefusal, sawCertificate)
}

// SAFEIO-002: a permission error is recorded, never escalated.
func TestWalkPermissionDenied(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("running as root; permission errors cannot be provoked")
	}
	dir := t.TempDir()
	locked := filepath.Join(dir, "locked")
	writeFile(t, filepath.Join(locked, "x.pem"), pemBlock("CERTIFICATE", testCertDER(t, "x.example")))
	if err := os.Chmod(locked, 0o000); err != nil {
		t.Skip(err)
	}
	t.Cleanup(func() { _ = os.Chmod(locked, 0o755) })

	_, c := walkDir(t, dir, PolicyOptions{})
	if countClass(c, SkippedPermissionDenied) == 0 {
		t.Fatalf("permission error not recorded: %v", c.Dispositions)
	}
}

// SAFEIO-002: a per-file size cap.
func TestWalkTooLarge(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "huge.pem"), make([]byte, 4096))
	writeFile(t, filepath.Join(dir, "ok.pem"), pemBlock("CERTIFICATE", testCertDER(t, "ok.example")))
	_, c := walkDir(t, dir, PolicyOptions{MaxFileBytes: 2048})
	if countClass(c, SkippedTooLarge) != 1 {
		t.Fatalf("SkippedTooLarge = %d: %v", countClass(c, SkippedTooLarge), c.Dispositions)
	}
	if c.CertificatesReturned != 1 {
		t.Fatalf("the small certificate was not read: %d", c.CertificatesReturned)
	}
}

// SAFEIO-007: FilesSeen must equal the sum of dispositions, on a tree that
// contains at least one file of every reachable skip class.
func TestCounterConservation(t *testing.T) {
	dir := t.TempDir()
	key := testRSAKey(t)
	writeFile(t, filepath.Join(dir, "a.pem"), pemBlock("CERTIFICATE", testCertDER(t, "a.example")))
	writeFile(t, filepath.Join(dir, "b.der"), testCertDER(t, "b.example"))
	writeFile(t, filepath.Join(dir, "k.key"), pemBlock("PRIVATE KEY", mustPKCS8(t, key)))
	writeFile(t, filepath.Join(dir, "store.p12"), []byte("binary"))
	writeFile(t, filepath.Join(dir, "id_rsa"), pemBlock("RSA PRIVATE KEY", x509.MarshalPKCS1PrivateKey(key)))
	writeFile(t, filepath.Join(dir, "raw.der"), mustPKCS8(t, key))
	writeFile(t, filepath.Join(dir, "empty.pem"), []byte("nothing here\n"))
	writeFile(t, filepath.Join(dir, "huge.pem"), make([]byte, 8192))
	_ = os.Symlink(filepath.Join(dir, "a.pem"), filepath.Join(dir, "link.pem"))

	_, c := walkDir(t, dir, PolicyOptions{MaxFileBytes: 4096})
	if ok, why := c.Conserved(); !ok {
		t.Fatalf("conservation: %s", why)
	}
	// Every skip class present must be named in the summary; none may be silent.
	if len(c.Summary()) == 0 {
		t.Fatal("summary is empty despite skips having occurred")
	}
	for class, n := range c.Dispositions {
		if n > 0 && !class.IsCertificate() && class.Human() == "" {
			t.Fatalf("skip class %v has no human-readable reason", class)
		}
	}
}

func mustPKCS8(t *testing.T, k any) []byte {
	t.Helper()
	der, err := x509.MarshalPKCS8PrivateKey(k)
	if err != nil {
		t.Fatalf("marshal pkcs8: %v", err)
	}
	return der
}

// Regression: a caller passing a path whose parent is a symlink must not be
// rejected from its own declared scope. macOS /var -> /private/var makes this
// the normal case there, not an edge case.
func TestWalkAcceptsSymlinkedRootPath(t *testing.T) {
	base := t.TempDir()
	real := filepath.Join(base, "real")
	writeFile(t, filepath.Join(real, "c.pem"), pemBlock("CERTIFICATE", testCertDER(t, "sym.example")))
	link := filepath.Join(base, "link")
	if err := os.Symlink(real, link); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	p, err := NewPolicy([]string{link}, PolicyOptions{})
	if err != nil {
		t.Fatal(err)
	}
	// Pass the UNRESOLVED path, as a caller naturally would.
	_, c, err := ReadCertificatesOnly(context.Background(), link, p)
	if err != nil {
		t.Fatalf("ReadCertificatesOnly with a symlinked root path: %v", err)
	}
	if c.CertificatesReturned != 1 {
		t.Fatalf("CertificatesReturned = %d, want 1", c.CertificatesReturned)
	}
}

// And the converse: a path that resolves OUTSIDE the policy roots is still refused.
func TestWalkRejectsRootResolvingOutsideScope(t *testing.T) {
	base := t.TempDir()
	inScope := filepath.Join(base, "in")
	outOfScope := filepath.Join(base, "out")
	writeFile(t, filepath.Join(inScope, "a.pem"), pemBlock("CERTIFICATE", testCertDER(t, "in.example")))
	writeFile(t, filepath.Join(outOfScope, "b.pem"), pemBlock("CERTIFICATE", testCertDER(t, "out.example")))

	escape := filepath.Join(inScope, "escape")
	if err := os.Symlink(outOfScope, escape); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	p, err := NewPolicy([]string{inScope}, PolicyOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := ReadCertificatesOnly(context.Background(), escape, p); err == nil {
		t.Fatal("a root resolving outside the policy roots was accepted")
	}
}
