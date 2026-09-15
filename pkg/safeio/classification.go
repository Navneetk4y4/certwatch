package safeio

// Classification is the disposition of one file encountered during a walk.
//
// The first two values mean "certificates were returned". Every other value
// means "nothing was returned, and here is exactly why" — a skip is never
// silent, because an unexplained gap in coverage is a lie by omission.
type Classification int

const (
	// ClassCertificatePEM: a PEM file from which one or more CERTIFICATE blocks
	// were decoded. Private-key blocks in the same file were skipped unbuffered.
	ClassCertificatePEM Classification = iota
	// ClassCertificateDER: a DER file whose structure matched a Certificate.
	ClassCertificateDER

	// SkippedForbiddenExtension: the extension was denied, or was not in the
	// allowlist. Decided before open(2).
	SkippedForbiddenExtension
	// SkippedPrivateKeyBlock: the file is, or contains, private-key material.
	// When the whole file is a key this is the file's disposition; when a key
	// block appears inside a certificate bundle it is counted at block level.
	SkippedPrivateKeyBlock
	// SkippedAmbiguousDER: could not be positively identified as a certificate.
	// Fail closed — ambiguity never resolves toward reading.
	SkippedAmbiguousDER
	// SkippedTooLarge: exceeded MaxFileBytes.
	SkippedTooLarge
	// SkippedSymlinkEscape: the path is a symlink. Symlinks are never followed.
	SkippedSymlinkEscape
	// SkippedPermissionDenied: EACCES. Recorded, never escalated.
	SkippedPermissionDenied

	// The following are walk-level dispositions. They are not among the eight
	// canonical classes in the security model but they must be counted, for the
	// same reason: the total must reconcile.

	// SkippedIrregularFile: device, FIFO, socket, or anything not a regular file.
	SkippedIrregularFile
	// SkippedDepthExceeded: deeper than MaxDepth below the root.
	SkippedDepthExceeded
	// SkippedBudgetExceeded: MaxFiles or MaxTotalBytes reached.
	SkippedBudgetExceeded
	// SkippedNoCertificates: opened and read, but contained no certificate.
	SkippedNoCertificates
	// SkippedReadError: an I/O error that is not a permission error.
	SkippedReadError
)

var classificationNames = map[Classification]string{
	ClassCertificatePEM:       "certificate_pem",
	ClassCertificateDER:       "certificate_der",
	SkippedForbiddenExtension: "skipped_forbidden_extension",
	SkippedPrivateKeyBlock:    "skipped_private_key_block",
	SkippedAmbiguousDER:       "skipped_ambiguous_der",
	SkippedTooLarge:           "skipped_too_large",
	SkippedSymlinkEscape:      "skipped_symlink_escape",
	SkippedPermissionDenied:   "skipped_permission_denied",
	SkippedIrregularFile:      "skipped_irregular_file",
	SkippedDepthExceeded:      "skipped_depth_exceeded",
	SkippedBudgetExceeded:     "skipped_budget_exceeded",
	SkippedNoCertificates:     "skipped_no_certificates",
	SkippedReadError:          "skipped_read_error",
}

// humanReasons back the plain-English summary the CLI prints. Coverage honesty
// is a product requirement, not a nicety: a user must be able to see what was
// not looked at and why.
var humanReasons = map[Classification]string{
	SkippedForbiddenExtension: "file type not opened (only .pem .crt .cer .der are read)",
	SkippedPrivateKeyBlock:    "contained private-key material, which is never read or transmitted",
	SkippedAmbiguousDER:       "could not be positively identified as a certificate, so it was not read",
	SkippedTooLarge:           "larger than the 1 MB certificate size limit",
	SkippedSymlinkEscape:      "a symbolic link, which is never followed",
	SkippedPermissionDenied:   "permission denied (the scanner never elevates privileges)",
	SkippedIrregularFile:      "not a regular file (device, socket or pipe)",
	SkippedDepthExceeded:      "deeper than the directory traversal limit",
	SkippedBudgetExceeded:     "the file or byte budget for this scan was reached",
	SkippedNoCertificates:     "contained no certificate",
	SkippedReadError:          "could not be read",
}

func (c Classification) String() string {
	if n, ok := classificationNames[c]; ok {
		return n
	}
	return "unknown"
}

// Human returns a plain-English explanation suitable for a CLI summary.
func (c Classification) Human() string {
	if r, ok := humanReasons[c]; ok {
		return r
	}
	return c.String()
}

// IsCertificate reports whether this classification carries certificate DER.
func (c Classification) IsCertificate() bool {
	return c == ClassCertificatePEM || c == ClassCertificateDER
}

// Result is one file's outcome. CertificateDER is populated ONLY when
// Class.IsCertificate() is true; for every other value it is nil. This is the
// type-level expression of the invariant.
type Result struct {
	Path           string
	Class          Classification
	CertificateDER [][]byte
	Reason         string
}
