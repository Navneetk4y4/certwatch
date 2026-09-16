package safeio

import (
	"io"
	"os"
	"strings"
)

// readSniffed handles .der, .cer and .crt, all of which occur as both PEM and
// DER in the wild. It reads the head of the file, decides, and dispatches.
func (w *walker) readSniffed(f *os.File, path string, size int64) (Result, int64, error) {
	head := make([]byte, 64)
	n, err := io.ReadFull(f, head)
	if err != nil && err != io.ErrUnexpectedEOF && err != io.EOF {
		return Result{}, int64(n), err
	}
	head = head[:n]

	if strings.Contains(string(head), pemBeginPrefix) {
		if _, err := f.Seek(0, io.SeekStart); err != nil {
			return Result{}, int64(n), err
		}
		return w.readPEM(f, path)
	}

	// Binary. Read the whole (already size-capped) file and classify structurally.
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return Result{}, int64(n), err
	}
	body := make([]byte, 0, size)
	buf := make([]byte, 32<<10)
	var read int64
	for {
		m, rerr := f.Read(buf)
		if m > 0 {
			read += int64(m)
			if read > w.policy.maxFileBytes {
				zero(body)
				return Result{Path: path, Class: SkippedTooLarge,
					Reason: "grew past the per-file limit while reading"}, read, nil
			}
			body = append(body, buf[:m]...)
		}
		if rerr == io.EOF {
			break
		}
		if rerr != nil {
			zero(body)
			return Result{}, read, rerr
		}
	}
	zero(buf)

	class, reason := classifyDER(body)
	res := Result{Path: path, Class: class, Reason: reason}
	if class == ClassCertificateDER {
		// classifyDER has already established that the outer TLV consumes the
		// whole input, so body is exactly one certificate and nothing else.
		// Copy it so the returned slice does not alias a buffer that also held
		// unclassified bytes.
		der := make([]byte, len(body))
		copy(der, body)
		res.CertificateDER = [][]byte{der}
		res.Reason = ""
	}
	zero(body)
	return res, read, nil
}

// classifyDER decides what a binary blob is, and fails closed.
//
// The only outcome that returns bytes to the caller is a positive structural
// match for an X.509 Certificate:
//
//	Certificate ::= SEQUENCE { tbsCertificate SEQUENCE,
//	                           signatureAlgorithm SEQUENCE,
//	                           signatureValue BIT STRING }
//
// No private-key encoding has that shape, and the check is structural rather
// than a full parse — deliberately, because a certificate that Go's crypto/x509
// rejects (negative serial, unusual string encoding) is MORE interesting to an
// inventory, not less, and must still reach x509norm to be recorded as
// unparseable rather than vanishing here.
//
// Everything that is not a positive match is skipped.
func classifyDER(b []byte) (Classification, string) {
	if len(b) < 8 {
		return SkippedAmbiguousDER, "too short to be a certificate"
	}
	if isPrivateKeyDER(b) {
		return SkippedPrivateKeyBlock, "DER-encoded private key"
	}
	if looksLikeCertificateDER(b) {
		return ClassCertificateDER, ""
	}
	return SkippedAmbiguousDER, "binary content did not match the structure of an X.509 certificate"
}

// isPrivateKeyDER matches the DER prefixes of the private-key encodings that
// occur in practice:
//
//	PKCS#8 PrivateKeyInfo : SEQUENCE { INTEGER 0, SEQUENCE alg, OCTET STRING }
//	PKCS#1 RSAPrivateKey  : SEQUENCE { INTEGER 0, INTEGER n, ... }
//	SEC1   ECPrivateKey   : SEQUENCE { INTEGER 1, OCTET STRING, ... }
//
// The first two share a prefix; both are keys, so the ambiguity does not matter.
func isPrivateKeyDER(b []byte) bool {
	tag, _, body, ok := readTLV(b)
	if !ok || tag != 0x30 {
		return false
	}
	// First element of the SEQUENCE.
	t0, _, v0, ok := readTLV(body)
	if !ok || t0 != 0x02 || len(v0) != 1 {
		return false
	}
	return v0[0] == 0x00 || v0[0] == 0x01
}

// looksLikeCertificateDER performs the three-element structural check AND
// requires the outer SEQUENCE to consume the entire input.
//
// The total-consumption requirement is not pedantry. Without it, a file whose
// content is `certificate || private-key` passes: the outer TLV describes only
// the certificate, the trailing key bytes are ignored by the check, and the
// caller then returns the WHOLE file as "certificate DER" — private key
// included. That is a direct INV-1 violation, it was found by adversarial
// review rather than by the canary, and this is the line that closes it.
func looksLikeCertificateDER(b []byte) bool {
	tag, hdrLen, body, ok := readTLV(b)
	if !ok || tag != 0x30 {
		return false
	}
	// The element must be the whole input. Anything appended is unaccounted-for
	// bytes, and unaccounted-for bytes are never returned.
	if hdrLen+len(body) != len(b) {
		return false
	}
	// tbsCertificate: SEQUENCE
	t0, _, _, rest, ok := readTLVSplit(body)
	if !ok || t0 != 0x30 {
		return false
	}
	// signatureAlgorithm: SEQUENCE
	t1, _, _, rest2, ok := readTLVSplit(rest)
	if !ok || t1 != 0x30 {
		return false
	}
	// signatureValue: BIT STRING
	t2, _, _, _, ok := readTLVSplit(rest2)
	if !ok || t2 != 0x03 {
		return false
	}
	return true
}

// readTLV parses one DER tag-length-value header and returns the value.
// It is deliberately minimal: no allocation, no recursion, bounded by the
// input slice, and it rejects indefinite-length encodings (not legal in DER).
func readTLV(b []byte) (tag byte, hdrLen int, value []byte, ok bool) {
	tag, hdrLen, length, ok := readTagLen(b)
	if !ok {
		return 0, 0, nil, false
	}
	if hdrLen+length > len(b) {
		return 0, 0, nil, false
	}
	return tag, hdrLen, b[hdrLen : hdrLen+length], true
}

// readTLVSplit is readTLV plus the remaining bytes after the element.
func readTLVSplit(b []byte) (tag byte, hdrLen int, value, rest []byte, ok bool) {
	tag, hdrLen, length, ok := readTagLen(b)
	if !ok {
		return 0, 0, nil, nil, false
	}
	end := hdrLen + length
	if end > len(b) {
		return 0, 0, nil, nil, false
	}
	return tag, hdrLen, b[hdrLen:end], b[end:], true
}

func readTagLen(b []byte) (tag byte, hdrLen, length int, ok bool) {
	if len(b) < 2 {
		return 0, 0, 0, false
	}
	tag = b[0]
	// Multi-byte tags are not used by any structure we accept.
	if tag&0x1f == 0x1f {
		return 0, 0, 0, false
	}
	l := b[1]
	if l == 0x80 {
		return 0, 0, 0, false // indefinite length: illegal in DER
	}
	if l < 0x80 {
		return tag, 2, int(l), true
	}
	n := int(l & 0x7f)
	if n == 0 || n > 4 || len(b) < 2+n {
		return 0, 0, 0, false
	}
	length = 0
	for i := 0; i < n; i++ {
		length = length<<8 | int(b[2+i])
	}
	if length < 0 {
		return 0, 0, 0, false
	}
	return tag, 2 + n, length, true
}
