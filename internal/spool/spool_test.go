package spool

import (
	"bytes"
	"errors"
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func open(t *testing.T, dir string, max int64) *Spool {
	t.Helper()
	s, err := Open(Options{Dir: dir, MaxBytes: max})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func put(t *testing.T, s *Spool, k Kind, body string) uint64 {
	t.Helper()
	seq, err := s.Put(k, "/v1/ingest/observations", []byte(body))
	if err != nil {
		t.Fatal(err)
	}
	return seq
}

func drain(t *testing.T, s *Spool) []string {
	t.Helper()
	var out []string
	for {
		it, ok, err := s.Oldest()
		if err != nil {
			t.Fatal(err)
		}
		if !ok {
			return out
		}
		out = append(out, string(it.Kind)+":"+string(it.Body))
		if err := s.Ack(it.Seq); err != nil {
			t.Fatal(err)
		}
	}
}

// frameSize is the on-disk size of an item, so tests can set caps exactly.
func frameSize(t *testing.T, k Kind, body string) int64 {
	dir := t.TempDir()
	s := open(t, dir, 1<<20)
	put(t, s, k, body)
	return s.Stats().Bytes
}

func TestItemsComeOutInTheOrderTheyWentIn(t *testing.T) {
	s := open(t, t.TempDir(), 0)
	put(t, s, Observation, "1")
	put(t, s, Verification, "2")
	put(t, s, Observation, "3")
	if got := strings.Join(drain(t, s), ","); got != "obs:1,ver:2,obs:3" {
		t.Fatal(got)
	}
	if st := s.Stats(); st.Items != 0 || st.Bytes != 0 {
		t.Fatalf("%+v", st)
	}
}

// S18 at the unit level: nothing is lost across a restart, order survives,
// and sequence numbers keep increasing.
func TestSpoolSurvivesRestart(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(Options{Dir: dir})
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 5; i++ {
		put(t, s, Verification, fmt.Sprint(i))
	}
	it, _, _ := s.Oldest()
	_ = s.Ack(it.Seq) // one sent before the "crash"
	s.Close()

	s2 := open(t, dir, 0)
	if st := s2.Stats(); st.Items != 4 {
		t.Fatalf("after restart: %+v", st)
	}
	seq := put(t, s2, Verification, "5")
	if seq != 6 {
		t.Fatalf("sequence restarted at %d", seq)
	}
	if got := strings.Join(drain(t, s2), ","); got != "ver:1,ver:2,ver:3,ver:4,ver:5" {
		t.Fatal(got)
	}
}

// Sent but not acknowledged — the server may have accepted it, the collector
// cannot know — means sent again. The batch_id inside makes that harmless.
func TestUnacknowledgedItemIsRedeliveredAfterRestart(t *testing.T) {
	dir := t.TempDir()
	s, _ := Open(Options{Dir: dir})
	put(t, s, Observation, "batch-1")
	if _, ok, _ := s.Oldest(); !ok {
		t.Fatal("missing")
	}
	s.Close() // crash before Ack
	s2 := open(t, dir, 0)
	it, ok, _ := s2.Oldest()
	if !ok || string(it.Body) != "batch-1" {
		t.Fatal("unacknowledged item lost")
	}
}

func TestOldestObservationsAreDroppedFirst(t *testing.T) {
	one := frameSize(t, Observation, "o0")
	s := open(t, t.TempDir(), 3*one)
	put(t, s, Observation, "o0")
	put(t, s, Observation, "o1")
	put(t, s, Observation, "o2")
	put(t, s, Observation, "o3") // evicts o0
	put(t, s, Observation, "o4") // evicts o1
	st := s.Stats()
	if st.Bytes > st.MaxBytes || st.DroppedObservations != 2 {
		t.Fatalf("%+v", st)
	}
	if got := strings.Join(drain(t, s), ","); got != "obs:o2,obs:o3,obs:o4" {
		t.Fatal(got)
	}
}

// Verification results are never dropped. Observations around them are.
func TestVerificationResultsAreNeverDropped(t *testing.T) {
	one := frameSize(t, Observation, "o0")
	s := open(t, t.TempDir(), 3*one)
	put(t, s, Verification, "v0")
	put(t, s, Observation, "o0")
	put(t, s, Verification, "v1")
	put(t, s, Verification, "v2") // must evict o0, not v0
	if got := s.Stats().DroppedObservations; got != 1 {
		t.Fatalf("dropped %d", got)
	}
	// Full of verifications: a new item of either kind is refused.
	for _, k := range []Kind{Observation, Verification} {
		if _, err := s.Put(k, "/p", []byte("xx")); !errors.Is(err, ErrFull) {
			t.Fatalf("%s into a spool of verifications: %v", k, err)
		}
	}
	if got := strings.Join(drain(t, s), ","); got != "ver:v0,ver:v1,ver:v2" {
		t.Fatal(got)
	}
	if st := s.Stats(); st.Refused != 2 {
		t.Fatalf("%+v", st)
	}
}

func TestOversizedItemIsRefused(t *testing.T) {
	s, err := Open(Options{Dir: t.TempDir(), MaxItemBytes: 1024})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if _, err := s.Put(Observation, "/p", bytes.Repeat([]byte("x"), 2048)); !errors.Is(err, ErrTooLarge) {
		t.Fatal(err)
	}
	if _, err := s.Put("other", "/p", []byte("x")); !errors.Is(err, ErrBadKind) {
		t.Fatal(err)
	}
}

// INV-5 on local disk: nothing that looks like a key is written, so nothing
// that looks like a key is on the disk afterwards.
func TestKeyMaterialNeverReachesDisk(t *testing.T) {
	dir := t.TempDir()
	s := open(t, dir, 0)
	for _, b := range []string{
		"-----BEGIN PRIVATE KEY-----\nMIIEv...",
		`{"private_key_pem":"x"}`,
		"-----BEGIN EC PRIVATE KEY-----",
	} {
		if _, err := s.Put(Observation, "/p", []byte(b)); !errors.Is(err, ErrKeyMaterial) {
			t.Fatalf("%q: %v", b, err)
		}
	}
	_ = filepath.Walk(dir, func(p string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return err
		}
		raw, _ := os.ReadFile(p)
		if bytes.Contains(bytes.ToUpper(raw), []byte("PRIVATE")) {
			t.Errorf("%s contains key-like bytes", p)
		}
		return nil
	})
}

func TestCorruptItemsAreDiscardedNotSent(t *testing.T) {
	cases := map[string]func(path string){
		"bit flip in body": func(p string) {
			b, _ := os.ReadFile(p)
			b[len(b)-1] ^= 0x01
			_ = os.WriteFile(p, b, 0o600)
		},
		"truncated": func(p string) {
			b, _ := os.ReadFile(p)
			_ = os.WriteFile(p, b[:len(b)-3], 0o600)
		},
		"garbage header": func(p string) { _ = os.WriteFile(p, []byte("nonsense\nbody"), 0o600) },
		"trailing bytes": func(p string) {
			b, _ := os.ReadFile(p)
			_ = os.WriteFile(p, append(b, 0), 0o600)
		},
		"empty file": func(p string) { _ = os.WriteFile(p, nil, 0o600) },
		"header retyped": func(p string) {
			b, _ := os.ReadFile(p)
			_ = os.WriteFile(p, bytes.Replace(b, []byte(`"kind":"obs"`), []byte(`"kind":"ver"`), 1), 0o600)
		},
		"path altered": func(p string) {
			b, _ := os.ReadFile(p)
			_ = os.WriteFile(p, bytes.Replace(b, []byte(`/v1/ingest/observations`), []byte(`/v1/ingest/xbservations`), 1), 0o600)
		},
	}
	for name, corrupt := range cases {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			s, _ := Open(Options{Dir: dir})
			put(t, s, Observation, `{"batch":"bad"}`)
			put(t, s, Observation, `{"batch":"good"}`)
			s.Close()
			corrupt(filepath.Join(dir, name1()))
			s2 := open(t, dir, 0)
			if got := strings.Join(drain(t, s2), ","); got != `obs:{"batch":"good"}` {
				t.Fatalf("got %s", got)
			}
			if st := s2.Stats(); st.Corrupt != 1 || st.Bytes != 0 {
				t.Fatalf("%+v", st)
			}
		})
	}
}

func name1() string { return name(1, Observation) }

func TestInterruptedWriteIsInvisibleAndCleanedUp(t *testing.T) {
	dir := t.TempDir()
	s, _ := Open(Options{Dir: dir})
	put(t, s, Observation, "whole")
	s.Close()
	tmp := filepath.Join(dir, name(2, Observation)+".tmp")
	_ = os.WriteFile(tmp, []byte(`{"v":1,"kind":"obs"`), 0o600) // crash mid-write
	s2 := open(t, dir, 0)
	if got := strings.Join(drain(t, s2), ","); got != "obs:whole" {
		t.Fatal(got)
	}
	if _, err := os.Stat(tmp); !os.IsNotExist(err) {
		t.Fatal("temporary file survived Open")
	}
}

func TestOneProcessPerSpool(t *testing.T) {
	dir := t.TempDir()
	s := open(t, dir, 0)
	if _, err := Open(Options{Dir: dir}); !errors.Is(err, ErrLocked) {
		t.Fatalf("second Open: %v", err)
	}
	s.Close()
	s2, err := Open(Options{Dir: dir})
	if err != nil {
		t.Fatalf("after Close: %v", err)
	}
	s2.Close()
}

func TestLoweredCapIsEnforcedOnOpen(t *testing.T) {
	dir := t.TempDir()
	s, _ := Open(Options{Dir: dir})
	for i := 0; i < 10; i++ {
		put(t, s, Observation, fmt.Sprintf("o%d", i))
	}
	one := s.Stats().Bytes / 10
	s.Close()
	s2 := open(t, dir, 3*one)
	if st := s2.Stats(); st.Bytes > st.MaxBytes || st.Items != 3 {
		t.Fatalf("%+v", st)
	}
	if got := strings.Join(drain(t, s2), ","); got != "obs:o7,obs:o8,obs:o9" {
		t.Fatal(got)
	}
}

func TestSpoolIsPrivateToItsOwner(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "spool")
	s := open(t, dir, 0)
	put(t, s, Observation, "x")
	di, _ := os.Stat(dir)
	if di.Mode().Perm() != 0o700 {
		t.Fatalf("dir mode %o", di.Mode().Perm())
	}
	fi, _ := os.Stat(filepath.Join(dir, name(1, Observation)))
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("file mode %o", fi.Mode().Perm())
	}
}

// Randomised: whatever the mix of puts and acks, the spool never exceeds its
// cap, its accounting matches the disk, and every accepted verification
// result comes out exactly once.
func TestBoundedUnderRandomLoad(t *testing.T) {
	for seed := int64(1); seed <= 8; seed++ {
		dir := t.TempDir()
		max := int64(4096)
		s := open(t, dir, max)
		r := rand.New(rand.NewSource(seed))
		var verIn, verOut []string
		for i := 0; i < 300; i++ {
			switch op := r.Intn(10); {
			case op < 4:
				body := strings.Repeat("o", r.Intn(300))
				_, err := s.Put(Observation, "/p", []byte(body))
				if err != nil && !errors.Is(err, ErrFull) {
					t.Fatal(err)
				}
			case op < 6:
				body := fmt.Sprintf("v%d-%s", i, strings.Repeat("v", r.Intn(300)))
				if _, err := s.Put(Verification, "/p", []byte(body)); err == nil {
					verIn = append(verIn, body)
				} else if !errors.Is(err, ErrFull) {
					t.Fatal(err)
				}
			default:
				it, ok, err := s.Oldest()
				if err != nil {
					t.Fatal(err)
				}
				if ok {
					if it.Kind == Verification {
						verOut = append(verOut, string(it.Body))
					}
					_ = s.Ack(it.Seq)
				}
			}
			st := s.Stats()
			if st.Bytes > max {
				t.Fatalf("seed %d: %d bytes over a %d cap", seed, st.Bytes, max)
			}
			var onDisk int64
			des, _ := os.ReadDir(dir)
			for _, de := range des {
				if nameRE.MatchString(de.Name()) {
					info, _ := de.Info()
					onDisk += info.Size()
				}
			}
			if onDisk != st.Bytes {
				t.Fatalf("seed %d: accounting %d, disk %d", seed, st.Bytes, onDisk)
			}
		}
		for _, it := range drain(t, s) {
			if strings.HasPrefix(it, "ver:") {
				verOut = append(verOut, strings.TrimPrefix(it, "ver:"))
			}
		}
		if strings.Join(verIn, "|") != strings.Join(verOut, "|") {
			t.Fatalf("seed %d: verification results lost or reordered", seed)
		}
	}
}
