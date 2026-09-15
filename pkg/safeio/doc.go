// Package safeio is the ONLY code in the collector permitted to open a file.
//
// # The invariant
//
// INV-1: the collector MUST NOT transmit any byte sequence that parses as, or is
// labelled as, private-key material.
//
// safeio is how that invariant is mechanical rather than documentary. Every other
// package in the collector receives already-classified bytes; none of them can
// open a file, and a CI check (internal/tools/importcheck) fails the build if
// os.Open, os.OpenFile, os.ReadFile, os.ReadDir or io/ioutil appear anywhere
// outside this package and internal/spool.
//
// # What it returns
//
// Certificate DER blocks, and nothing else. A file containing a private key is
// skipped and counted. A file that MIGHT contain a private key is skipped and
// counted. Ambiguity always resolves toward skipping: see classifyDER.
//
// # What it never does
//
//   - follow a symlink (O_NOFOLLOW at open, not merely a check at stat)
//   - open a file whose extension is not in the allowlist
//   - buffer the body of a PEM block labelled as a private key
//   - open a device, FIFO, socket or anything under /proc, /sys or /dev
//   - escalate on a permission error
//   - skip anything silently
//
// # Reading configuration
//
// ReadConfigFile exists so that "safeio is the only code that opens a file"
// stays literally true even for scope.yaml. It applies the same symlink and
// size protections and returns raw bytes; it is NOT a general file reader and
// its size cap is small deliberately.
//
// References: project_1_security_model.md §3, project_1_full_development_plan.md §11.1.
package safeio
