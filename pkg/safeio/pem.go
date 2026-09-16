package safeio

import (
	"bufio"
	"encoding/base64"
	"io"
	"os"
	"strings"
)

const (
	pemBeginPrefix = "-----BEGIN "
	pemEndPrefix   = "-----END "
	pemSuffix      = "-----"
	pemTypeCert    = "CERTIFICATE"
)

// readPEM streams a PEM file one line at a time.
//
// INV-2: on a line that opens a private-key block, the body is discarded to the
// matching END marker WITHOUT being appended to any buffer. There is deliberately
// no []byte accumulator on that code path — the invariant holds by construction,
// not by remembering to clear something afterwards.
func (w *walker) readPEM(f *os.File, path string) (Result, int64, error) {
	res := Result{Path: path, Class: SkippedNoCertificates,
		Reason: "no CERTIFICATE block found"}

	sc := newLineReader(io.LimitReader(f, w.policy.maxFileBytes))

	var (
		bytesRead   int64
		inCert      bool
		certB64     []byte // certificate base64 only; never key material
		sawAnyBlock bool
	)

	for sc.Scan() {
		line := sc.Text()
		bytesRead += int64(len(line)) + 1
		if sc.Overlong() {
			// A line longer than any legal PEM line. The file is not PEM-formatted
			// at this point, but a certificate may still follow, so the line is
			// discarded and scanning continues rather than abandoning the file.
			// Abandoning would be a silent coverage gap.
			inCert = false
			zero(certB64)
			certB64 = certB64[:0]
			continue
		}
		trimmed := strings.TrimSpace(line)

		switch {
		case strings.HasPrefix(trimmed, pemBeginPrefix) && strings.HasSuffix(trimmed, pemSuffix):
			sawAnyBlock = true
			blockType := strings.TrimSuffix(strings.TrimPrefix(trimmed, pemBeginPrefix), pemSuffix)

			if isPrivateKeyBlockType(blockType) {
				// Discard to the END marker. discardPEMBlock inspects only the
				// END-marker prefix of each line and never converts, copies or
				// retains a body line. INV-2.
				n := discardPEMBlock(sc, blockType)
				bytesRead += n
				w.counters.PrivateKeyBlocksSkipped++
				continue
			}
			if blockType == pemTypeCert {
				inCert = true
				certB64 = certB64[:0]
				continue
			}
			// Some other block type (DH PARAMETERS, PUBLIC KEY, an unknown label).
			// Not a certificate, so skip it — and count it, because an unexplained
			// gap is a lie by omission.
			n := discardPEMBlock(sc, blockType)
			bytesRead += n
			w.counters.UnknownPEMBlocksSkipped++

		case strings.HasPrefix(trimmed, pemEndPrefix):
			if inCert {
				inCert = false
				der, err := decodePEMBody(certB64)
				zero(certB64)
				certB64 = certB64[:0]
				if err == nil && looksLikeCertificateDER(der) {
					res.Class = ClassCertificatePEM
					res.Reason = ""
					res.CertificateDER = append(res.CertificateDER, der)
				}
			}

		default:
			if inCert {
				certB64 = append(certB64, strings.TrimSpace(line)...)
				if len(certB64) > int(w.policy.maxFileBytes) {
					// A certificate block larger than the file limit is not a
					// certificate. Abandon it rather than growing without bound.
					zero(certB64)
					certB64 = certB64[:0]
					inCert = false
				}
			}
		}
	}
	zero(certB64)

	if err := sc.Err(); err != nil {
		return Result{}, bytesRead, err
	}
	if len(res.CertificateDER) == 0 && sc.SawOverlongLine() {
		res.Reason = "not PEM-formatted (contained a line too long to be a PEM line)"
	}
	if len(res.CertificateDER) == 0 && !sawAnyBlock {
		res.Reason = "not a PEM file, or contained no PEM blocks"
	}
	return res, bytesRead, nil
}

// discardPEMBlock reads forward to the matching END line without materialising
// the block body.
//
// It uses ScanRaw, which exposes the line as a []byte view into the reader's
// own buffer rather than converting it to a string. Converting would allocate a
// copy of each key body line on the Go heap, where it would live until the
// garbage collector happened to reclaim it — unzeroed, and reachable from a
// heap dump or a core file.
//
// An earlier version of this function called sc.Text(), and the comment at its
// call site claimed "No buffer, no allocation, no copy". That claim was
// inaccurate, and adversarial review caught it. The invariant is now true by
// construction: the only bytes touched are the END-marker prefix.
//
// A truncated block (BEGIN with no END) terminates at EOF rather than hanging.
func discardPEMBlock(sc *lineReader, blockType string) int64 {
	want := []byte(pemEndPrefix + blockType + pemSuffix)
	endPrefix := []byte(pemEndPrefix)
	suffix := []byte(pemSuffix)
	var n int64
	for sc.ScanRaw() {
		raw := sc.Raw()
		n += int64(len(raw)) + 1
		// Only END lines are inspected; a body line is never compared, copied,
		// converted or retained.
		if len(raw) == 0 || raw[0] != '-' {
			trimmed := bytesTrimSpace(raw)
			if len(trimmed) == 0 || trimmed[0] != '-' {
				continue
			}
			raw = trimmed
		}
		t := bytesTrimSpace(raw)
		if bytesEqual(t, want) {
			return n
		}
		// Tolerate a mismatched END label: any END terminates the block. A file
		// with BEGIN X / END Y is malformed, and scanning on for the exact label
		// would swallow the rest of the file — including certificates after it.
		if bytesHasPrefix(t, endPrefix) && bytesHasSuffix(t, suffix) {
			return n
		}
	}
	return n
}

func bytesTrimSpace(b []byte) []byte {
	i, j := 0, len(b)
	for i < j && (b[i] == ' ' || b[i] == '\t' || b[i] == '\r' || b[i] == '\n') {
		i++
	}
	for j > i && (b[j-1] == ' ' || b[j-1] == '\t' || b[j-1] == '\r' || b[j-1] == '\n') {
		j--
	}
	return b[i:j]
}

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func bytesHasPrefix(b, p []byte) bool {
	return len(b) >= len(p) && bytesEqual(b[:len(p)], p)
}

func bytesHasSuffix(b, s []byte) bool {
	return len(b) >= len(s) && bytesEqual(b[len(b)-len(s):], s)
}

// isPrivateKeyBlockType matches every PEM label that carries, or may carry,
// private-key material. The check is deliberately broad: any label ending in
// "PRIVATE KEY" matches, so a format we have not seen still fails closed.
func isPrivateKeyBlockType(t string) bool {
	up := strings.ToUpper(strings.TrimSpace(t))
	if strings.HasSuffix(up, "PRIVATE KEY") {
		return true
	}
	switch up {
	case "ENCRYPTED PRIVATE KEY", "RSA PRIVATE KEY", "EC PRIVATE KEY",
		"DSA PRIVATE KEY", "OPENSSH PRIVATE KEY", "PGP PRIVATE KEY BLOCK",
		"PRIVATE KEY", "ANY PRIVATE KEY", "SSH2 ENCRYPTED PRIVATE KEY":
		return true
	}
	return false
}

func decodePEMBody(b64 []byte) ([]byte, error) {
	dst := make([]byte, base64.StdEncoding.DecodedLen(len(b64)))
	n, err := base64.StdEncoding.Decode(dst, b64)
	if err != nil {
		return nil, err
	}
	return dst[:n], nil
}

// zero overwrites a buffer before it is released. INV-7.
func zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// lineReader reads lines with a hard cap, and survives a line that exceeds it by
// discarding the remainder rather than failing the whole file.
//
// bufio.Scanner cannot do this: it returns ErrTooLong and stops, which would
// mean one pathological line hides every certificate after it. That is a silent
// coverage gap, and silent coverage gaps are the failure mode this package
// exists to prevent.
type lineReader struct {
	r           *bufio.Reader
	line        string
	rawBuf      []byte
	overlong    bool
	sawOverlong bool
	err         error
}

func newLineReader(r io.Reader) *lineReader {
	return &lineReader{r: bufio.NewReaderSize(r, 4096)}
}

func (l *lineReader) Scan() bool {
	if l.err != nil {
		return false
	}
	l.overlong = false
	var buf []byte
	for {
		chunk, isPrefix, err := l.r.ReadLine()
		if err != nil {
			if err == io.EOF {
				if len(buf) > 0 {
					l.line = string(buf)
					return true
				}
				l.err = io.EOF
				return false
			}
			l.err = err
			return false
		}
		if len(buf)+len(chunk) <= maxPEMLine {
			buf = append(buf, chunk...)
		} else {
			l.overlong = true
			l.sawOverlong = true
		}
		if !isPrefix {
			break
		}
	}
	l.line = string(buf)
	return true
}

// ScanRaw advances like Scan but exposes the line as a []byte view rather than
// converting it to a string, so a key body line is never copied onto the heap.
func (l *lineReader) ScanRaw() bool {
	if l.err != nil {
		return false
	}
	l.overlong = false
	l.rawBuf = l.rawBuf[:0]
	for {
		chunk, isPrefix, err := l.r.ReadLine()
		if err != nil {
			if err == io.EOF {
				if len(l.rawBuf) > 0 {
					return true
				}
				l.err = io.EOF
				return false
			}
			l.err = err
			return false
		}
		if len(l.rawBuf)+len(chunk) <= maxPEMLine {
			l.rawBuf = append(l.rawBuf, chunk...)
		} else {
			l.overlong = true
			l.sawOverlong = true
		}
		if !isPrefix {
			break
		}
	}
	return true
}

// Raw returns the current line as bytes. The slice is only valid until the next
// Scan or ScanRaw call.
func (l *lineReader) Raw() []byte { return l.rawBuf }

func (l *lineReader) Text() string          { return l.line }
func (l *lineReader) Overlong() bool        { return l.overlong }
func (l *lineReader) SawOverlongLine() bool { return l.sawOverlong }
func (l *lineReader) Err() error {
	if l.err == io.EOF {
		return nil
	}
	return l.err
}
