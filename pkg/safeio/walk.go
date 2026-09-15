package safeio

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"syscall"
)

// ReadCertificatesOnly walks root, bounded by p, and returns certificate DER
// blocks only. It never returns key material.
//
// root must lie at or below one of the policy's roots; otherwise this is an
// error, not a skip — a caller asking for a path outside declared scope has a
// bug or has been given a hostile instruction, and either way the answer is no.
//
// The returned Counters reconcile: FilesSeen equals the sum of dispositions.
func ReadCertificatesOnly(ctx context.Context, root string, p *Policy) ([]Result, *Counters, error) {
	if p == nil {
		return nil, nil, errors.New("safeio: nil policy")
	}
	cleanRoot := filepath.Clean(root)
	if !filepath.IsAbs(cleanRoot) {
		return nil, nil, errors.New("safeio: root must be absolute")
	}
	// Resolve the caller's path the same way NewPolicy resolved its own roots,
	// so the containment check compares like with like. Without this, a caller
	// on a system where a parent directory is a symlink (macOS /var ->
	// /private/var is the common case) is rejected from its own declared scope.
	//
	// This does not weaken containment: a path resolving OUTSIDE the policy's
	// roots still fails the check below, which is the correct answer.
	if resolved, err := filepath.EvalSymlinks(cleanRoot); err == nil {
		cleanRoot = filepath.Clean(resolved)
	}
	inScope := false
	for _, r := range p.roots {
		if Contains(r, cleanRoot) {
			inScope = true
			break
		}
	}
	if !inScope {
		return nil, nil, errors.New("safeio: root is outside the policy's declared roots")
	}

	ctx, cancel := context.WithTimeout(ctx, p.timeout)
	defer cancel()

	w := &walker{policy: p, counters: newCounters(), ctx: ctx}
	w.descend(cleanRoot, 0)

	if ctx.Err() != nil {
		w.counters.TimedOut = true
		if !w.counters.Truncated {
			w.counters.Truncated = true
			w.counters.TruncatedWhy = "timeout reached while walking"
		}
	}
	return w.results, w.counters, nil
}

type walker struct {
	policy    *Policy
	counters  *Counters
	results   []Result
	ctx       context.Context
	stopped   bool
	bytesUsed int64
}

func (w *walker) stop(why string) {
	if !w.stopped {
		w.stopped = true
		w.counters.Truncated = true
		w.counters.TruncatedWhy = why
	}
}

func (w *walker) descend(dir string, depth int) {
	if w.stopped || w.ctx.Err() != nil {
		return
	}
	if depth > w.policy.maxDepth {
		// The directory itself is not a file, so this is recorded as a
		// truncation rather than a per-file disposition.
		w.stop("directory traversal depth limit reached")
		return
	}
	if isRefusedPath(dir) {
		return
	}

	// os.ReadDir returns DirEntry values whose Type() comes from the directory
	// entry itself — symlink-aware without an extra stat, and crucially NOT
	// following the link. This is the Lstat semantics the design requires.
	entries, err := os.ReadDir(dir)
	if err != nil {
		// A directory we cannot read is a coverage gap; record it as a file-level
		// disposition so the total reconciles and the user sees it.
		w.counters.record(classifyPathError(err))
		w.results = append(w.results, Result{
			Path: dir, Class: classifyPathError(err), Reason: "directory could not be listed: " + err.Error(),
		})
		return
	}
	w.counters.DirsVisited++

	// Deterministic order so a truncated walk truncates the same way twice.
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })

	for _, e := range entries {
		if w.stopped || w.ctx.Err() != nil {
			return
		}
		full := filepath.Join(dir, e.Name())
		typ := e.Type()

		switch {
		case typ&fs.ModeSymlink != 0:
			// Never followed — not for files, not for directories, and not even
			// when the target would have been allowed. A symlink into
			// /etc/ssl/private/ is exactly the attack this closes, and an
			// exception for "safe" links reintroduces the decision we removed.
			w.emitSkip(full, SkippedSymlinkEscape, "symbolic link; symlinks are never followed")

		case e.IsDir():
			w.descend(full, depth+1)

		case typ.IsRegular():
			w.visitFile(full, e)

		default:
			// Device, FIFO, socket, irregular. Refused by type before open, so a
			// read on a FIFO can never block the walk.
			w.emitSkip(full, SkippedIrregularFile, "not a regular file ("+typ.String()+")")
		}
	}
}

func (w *walker) visitFile(path string, e fs.DirEntry) {
	if w.counters.FilesSeen >= w.policy.maxFiles {
		w.stop("file count limit reached")
		return
	}

	// Extension gate runs BEFORE open(2). Nothing outside the allowlist is ever
	// opened, so a .p12 is rejected without a single byte of it being read.
	if allowed, reason := extensionDecision(path); !allowed {
		w.emitSkip(path, SkippedForbiddenExtension, reason)
		return
	}

	info, err := e.Info()
	if err != nil {
		w.emitSkip(path, classifyPathError(err), "could not stat: "+err.Error())
		return
	}
	if info.Size() > w.policy.maxFileBytes {
		w.emitSkip(path, SkippedTooLarge, "larger than the per-file limit")
		return
	}
	if w.bytesUsed+info.Size() > w.policy.maxTotalBytes {
		w.stop("total byte budget reached")
		return
	}

	res, read, err := w.readOne(path, info.Size())
	w.bytesUsed += read
	w.counters.BytesRead += read
	if err != nil {
		w.emitSkip(path, classifyPathError(err), err.Error())
		return
	}
	w.counters.record(res.Class)
	if res.Class.IsCertificate() {
		w.counters.CertificatesReturned += len(res.CertificateDER)
	}
	w.results = append(w.results, res)
}

// readOne opens exactly one file with O_NOFOLLOW and classifies its contents.
//
// O_NOFOLLOW is the TOCTOU closure. The directory entry told us this was a
// regular file; between that moment and this one an attacker may have replaced
// it with a symlink. Checking twice would narrow the window; O_NOFOLLOW removes
// it, because the kernel refuses the open rather than following the link.
func (w *walker) readOne(path string, size int64) (Result, int64, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		if errors.Is(err, syscall.ELOOP) {
			return Result{Path: path, Class: SkippedSymlinkEscape,
				Reason: "replaced by a symbolic link between listing and open"}, 0, nil
		}
		return Result{}, 0, err
	}
	defer f.Close()

	ext := lowerExt(path)
	if ext == ".der" || ext == ".cer" || ext == ".crt" {
		// .cer and .crt are ambiguous in the wild: both PEM and DER occur. Sniff.
		return w.readSniffed(f, path, size)
	}
	return w.readPEM(f, path)
}

func (w *walker) emitSkip(path string, class Classification, reason string) {
	w.counters.record(class)
	w.results = append(w.results, Result{Path: path, Class: class, Reason: reason})
}

func classifyPathError(err error) Classification {
	if errors.Is(err, os.ErrPermission) || errors.Is(err, syscall.EACCES) || errors.Is(err, syscall.EPERM) {
		return SkippedPermissionDenied
	}
	if errors.Is(err, syscall.ELOOP) {
		return SkippedSymlinkEscape
	}
	return SkippedReadError
}

func lowerExt(path string) string {
	ext := filepath.Ext(path)
	b := []byte(ext)
	for i := range b {
		if b[i] >= 'A' && b[i] <= 'Z' {
			b[i] += 'a' - 'A'
		}
	}
	return string(b)
}
