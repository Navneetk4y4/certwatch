// Package spool is the collector's bounded local queue.
//
// PROTO-004, build item 116. When the control plane is unreachable the
// collector keeps verifying and keeps what it found here, and sends it when
// the connection returns. "Verification continues; the customer loses
// visibility, not protection."
//
// # The rules, each a property of this package rather than of its callers
//
//   - Bounded. Total size never exceeds MaxBytes (100 MB by default) — not
//     after a crash, not after the cap is lowered between runs.
//   - Drop OLDEST OBSERVATIONS first, NEVER verification results. If only
//     verifications are left, a new item is refused rather than an old
//     verification being discarded.
//   - FIFO. Items are sent in the order they were produced.
//   - Crash-safe. An item is written to a temporary file, fsynced, then
//     renamed; a crash leaves either the whole item or nothing. Leftover
//     temporaries are removed on Open.
//   - Removed ONLY on Ack, which the uploader calls only after a 2xx. A crash
//     between the server accepting and the Ack means the item is sent again;
//     the batch_id inside it makes that a no-op server-side.
//   - Corruption is detected (SHA-256 over kind, path and body) and the item
//     is discarded and counted, never sent.
//   - No key material. Put refuses anything pkg/keyscan matches: a leak to
//     local disk is still a leak (INV-5, canary-inspected).
//   - One process. An exclusive lock on the directory stops two collectors
//     interleaving one spool.
//
// This is the one package outside pkg/safeio permitted direct file I/O
// (CI-007), scoped to its own directory.
package spool

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"sync"
	"syscall"

	"github.com/certwatch/certwatch/pkg/keyscan"
)

// Kind is what an item holds. It decides what may be dropped.
type Kind string

const (
	Observation  Kind = "obs"
	Verification Kind = "ver"
)

const (
	// DefaultMaxBytes is the spec's 100 MB.
	DefaultMaxBytes = 100 << 20
	// DefaultMaxItemBytes is one batch at the protocol's 5 MB cap, plus
	// framing.
	DefaultMaxItemBytes = 5<<20 + 4096
)

var (
	ErrFull        = errors.New("spool: full of verification results; item refused")
	ErrTooLarge    = errors.New("spool: item exceeds the per-item cap")
	ErrKeyMaterial = errors.New("spool: item contains private-key material; refused")
	ErrLocked      = errors.New("spool: directory is locked by another process")
	ErrBadKind     = errors.New("spool: unknown item kind")
)

// Options configures a spool.
type Options struct {
	Dir          string
	MaxBytes     int64
	MaxItemBytes int64
}

// Item is one queued request.
type Item struct {
	Seq  uint64
	Kind Kind
	Path string
	Body []byte
}

// Stats is what the heartbeat reports.
type Stats struct {
	Items               int
	Bytes               int64
	MaxBytes            int64
	DroppedObservations uint64
	Refused             uint64
	Corrupt             uint64
}

// PctFull is spool_pct_full in the heartbeat.
func (s Stats) PctFull() float64 {
	if s.MaxBytes <= 0 {
		return 0
	}
	p := float64(s.Bytes) / float64(s.MaxBytes)
	if p > 1 {
		p = 1
	}
	return p
}

type entry struct {
	seq  uint64
	kind Kind
	size int64
}

// Spool is a directory of items.
type Spool struct {
	mu    sync.Mutex
	opt   Options
	lock  *os.File
	items []entry // ascending seq
	bytes int64
	next  uint64
	st    Stats
}

var nameRE = regexp.MustCompile(`^(\d{20})-(obs|ver)\.spool$`)

func name(seq uint64, k Kind) string { return fmt.Sprintf("%020d-%s.spool", seq, k) }

// Open opens or creates a spool and takes its lock.
func Open(opt Options) (*Spool, error) {
	if opt.MaxBytes <= 0 {
		opt.MaxBytes = DefaultMaxBytes
	}
	if opt.MaxItemBytes <= 0 {
		opt.MaxItemBytes = DefaultMaxItemBytes
	}
	if err := os.MkdirAll(opt.Dir, 0o700); err != nil {
		return nil, err
	}
	// The spool holds certificate metadata about the customer's estate. Not
	// secret, but nobody else on the host needs to read it.
	if err := os.Chmod(opt.Dir, 0o700); err != nil {
		return nil, err
	}
	lf, err := os.OpenFile(filepath.Join(opt.Dir, ".lock"), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(lf.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		lf.Close()
		return nil, ErrLocked
	}
	s := &Spool{opt: opt, lock: lf, next: 1}
	if err := s.load(); err != nil {
		s.Close()
		return nil, err
	}
	return s, nil
}

func (s *Spool) load() error {
	des, err := os.ReadDir(s.opt.Dir)
	if err != nil {
		return err
	}
	for _, de := range des {
		n := de.Name()
		if filepath.Ext(n) == ".tmp" {
			// A write that never reached its rename. Never visible, never sent.
			_ = os.Remove(filepath.Join(s.opt.Dir, n))
			continue
		}
		m := nameRE.FindStringSubmatch(n)
		if m == nil || !de.Type().IsRegular() {
			continue
		}
		seq, _ := strconv.ParseUint(m[1], 10, 64)
		info, err := de.Info()
		if err != nil {
			return err
		}
		s.items = append(s.items, entry{seq: seq, kind: Kind(m[2]), size: info.Size()})
		s.bytes += info.Size()
		if seq >= s.next {
			s.next = seq + 1
		}
	}
	sort.Slice(s.items, func(i, j int) bool { return s.items[i].seq < s.items[j].seq })
	// The cap may have been lowered since the last run.
	s.dropObservationsUntil(0)
	return nil
}

// Close releases the lock.
func (s *Spool) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.lock == nil {
		return nil
	}
	_ = syscall.Flock(int(s.lock.Fd()), syscall.LOCK_UN)
	err := s.lock.Close()
	s.lock = nil
	return err
}

type header struct {
	V      int    `json:"v"`
	Kind   Kind   `json:"kind"`
	Path   string `json:"path"`
	Len    int    `json:"len"`
	SHA256 string `json:"sha256"`
}

func digest(k Kind, path string, body []byte) string {
	h := sha256.New()
	fmt.Fprintf(h, "%s\n%s\n", k, path)
	h.Write(body)
	return hex.EncodeToString(h.Sum(nil))
}

// Put appends an item. It returns the item's sequence number.
func (s *Spool) Put(k Kind, path string, body []byte) (uint64, error) {
	if k != Observation && k != Verification {
		return 0, ErrBadKind
	}
	if keyscan.Scan(body) != "" || keyscan.Scan([]byte(path)) != "" {
		return 0, ErrKeyMaterial
	}
	hj, _ := json.Marshal(header{V: 1, Kind: k, Path: path, Len: len(body), SHA256: digest(k, path, body)})
	frame := append(append(hj, '\n'), body...)
	size := int64(len(frame))

	s.mu.Lock()
	defer s.mu.Unlock()
	if size > s.opt.MaxItemBytes || size > s.opt.MaxBytes {
		s.st.Refused++
		return 0, ErrTooLarge
	}
	s.dropObservationsUntil(size)
	if s.bytes+size > s.opt.MaxBytes {
		// Only verification results remain. They are never dropped, so the
		// new item is the one that does not get in.
		s.st.Refused++
		return 0, ErrFull
	}
	seq := s.next
	final := filepath.Join(s.opt.Dir, name(seq, k))
	tmp := final + ".tmp"
	if err := writeSync(tmp, frame); err != nil {
		_ = os.Remove(tmp)
		return 0, err
	}
	if err := os.Rename(tmp, final); err != nil {
		_ = os.Remove(tmp)
		return 0, err
	}
	if err := syncDir(s.opt.Dir); err != nil {
		return 0, err
	}
	s.next++
	s.items = append(s.items, entry{seq: seq, kind: k, size: size})
	s.bytes += size
	return seq, nil
}

// dropObservationsUntil removes the oldest observation items until `extra`
// more bytes would fit. Caller holds mu.
func (s *Spool) dropObservationsUntil(extra int64) {
	for i := 0; s.bytes+extra > s.opt.MaxBytes && i < len(s.items); {
		if s.items[i].kind != Observation {
			i++
			continue
		}
		e := s.items[i]
		if err := os.Remove(filepath.Join(s.opt.Dir, name(e.seq, e.kind))); err != nil && !os.IsNotExist(err) {
			i++ // cannot remove it; leave it accounted for
			continue
		}
		s.items = append(s.items[:i], s.items[i+1:]...)
		s.bytes -= e.size
		s.st.DroppedObservations++
	}
}

// Oldest returns the oldest intact item. Corrupt items met on the way are
// removed and counted.
func (s *Spool) Oldest() (Item, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for len(s.items) > 0 {
		e := s.items[0]
		it, err := s.read(e)
		if err == nil {
			return it, true, nil
		}
		if !errors.Is(err, errCorrupt) {
			return Item{}, false, err
		}
		_ = os.Remove(filepath.Join(s.opt.Dir, name(e.seq, e.kind)))
		s.items = s.items[1:]
		s.bytes -= e.size
		s.st.Corrupt++
	}
	return Item{}, false, nil
}

var errCorrupt = errors.New("spool: corrupt item")

func (s *Spool) read(e entry) (Item, error) {
	f, err := os.Open(filepath.Join(s.opt.Dir, name(e.seq, e.kind)))
	if err != nil {
		if os.IsNotExist(err) {
			return Item{}, errCorrupt
		}
		return Item{}, err
	}
	defer f.Close()
	r := bufio.NewReader(io.LimitReader(f, s.opt.MaxItemBytes+1))
	line, err := r.ReadBytes('\n')
	if err != nil {
		return Item{}, errCorrupt
	}
	var h header
	dec := json.NewDecoder(bytes.NewReader(line))
	dec.DisallowUnknownFields()
	if dec.Decode(&h) != nil || h.V != 1 || h.Kind != e.kind || h.Len < 0 ||
		int64(h.Len) > s.opt.MaxItemBytes {
		return Item{}, errCorrupt
	}
	body := make([]byte, h.Len)
	if _, err := io.ReadFull(r, body); err != nil {
		return Item{}, errCorrupt
	}
	if _, err := r.ReadByte(); err != io.EOF {
		return Item{}, errCorrupt // trailing bytes
	}
	if digest(h.Kind, h.Path, body) != h.SHA256 {
		return Item{}, errCorrupt
	}
	return Item{Seq: e.seq, Kind: h.Kind, Path: h.Path, Body: body}, nil
}

// Ack removes an item once the server has accepted it.
func (s *Spool) Ack(seq uint64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i, e := range s.items {
		if e.seq != seq {
			continue
		}
		if err := os.Remove(filepath.Join(s.opt.Dir, name(e.seq, e.kind))); err != nil && !os.IsNotExist(err) {
			return err
		}
		s.items = append(s.items[:i], s.items[i+1:]...)
		s.bytes -= e.size
		return syncDir(s.opt.Dir)
	}
	return nil
}

// Stats reports the spool's state.
func (s *Spool) Stats() Stats {
	s.mu.Lock()
	defer s.mu.Unlock()
	st := s.st
	st.Items, st.Bytes, st.MaxBytes = len(s.items), s.bytes, s.opt.MaxBytes
	return st
}

func writeSync(path string, b []byte) error {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.Write(b); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

func syncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}
