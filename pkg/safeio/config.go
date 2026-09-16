package safeio

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"syscall"
)

// configExtensions is the allowlist for ReadConfigFile.
var configExtensions = map[string]bool{
	".yaml": true, ".yml": true, ".json": true, ".txt": true, ".conf": true, ".list": true,
}

var configExtensionList = []string{".yaml", ".yml", ".json", ".txt", ".conf", ".list"}

// MaxConfigBytes bounds a configuration file. A scope file is a few kilobytes;
// the cap is small deliberately so this cannot become a general file reader.
const MaxConfigBytes = 256 << 10

// ReadConfigFile reads one configuration file (scope.yaml) with the same
// symlink and size protections the certificate walk uses.
//
// It exists so that "safeio is the only code in the collector that opens a file"
// stays literally true. The alternative — letting internal/scopecfg call
// os.Open — would add a third entry to the import-check exception list, and
// every entry on that list is a place the boundary has to be re-argued.
//
// It is NOT a general file reader:
//   - the path must be a regular file, not a symlink, not a device
//   - the size cap is 256 KiB
//   - it returns raw bytes and makes no attempt to interpret them
//
// A caller must not use this to read anything that might contain key material.
// Nothing in the current design does, and the extension gate below enforces it.
func ReadConfigFile(path string) ([]byte, error) {
	if !filepath.IsAbs(path) {
		return nil, fmt.Errorf("safeio: config path %q must be absolute", path)
	}
	if isRefusedPath(path) {
		return nil, fmt.Errorf("safeio: config path %q is under a refused prefix", path)
	}
	// An ALLOWLIST, not just a denylist. With a denylist alone this function
	// would happily read /etc/shadow (no extension, therefore not denied) —
	// which makes it a general file reader wearing a config-reader label, and
	// the whole point of routing config through safeio is that it is not one.
	ext := lowerExt(path)
	if !configExtensions[ext] {
		return nil, fmt.Errorf("safeio: refusing to open %q as configuration: "+
			"only %v files are read here", path, configExtensionList)
	}

	fi, err := os.Lstat(path)
	if err != nil {
		return nil, fmt.Errorf("safeio: %w", err)
	}
	if fi.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("safeio: config path %q is a symbolic link; symlinks are never followed", path)
	}
	if !fi.Mode().IsRegular() {
		return nil, fmt.Errorf("safeio: config path %q is not a regular file", path)
	}
	if fi.Size() > MaxConfigBytes {
		return nil, fmt.Errorf("safeio: config file %q is %d bytes, over the %d byte limit", path, fi.Size(), MaxConfigBytes)
	}

	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		if errors.Is(err, syscall.ELOOP) {
			return nil, fmt.Errorf("safeio: config path %q became a symbolic link", path)
		}
		return nil, fmt.Errorf("safeio: %w", err)
	}
	defer f.Close()

	b, err := io.ReadAll(io.LimitReader(f, MaxConfigBytes+1))
	if err != nil {
		return nil, fmt.Errorf("safeio: %w", err)
	}
	if len(b) > MaxConfigBytes {
		zero(b)
		return nil, fmt.Errorf("safeio: config file %q exceeded the %d byte limit while reading", path, MaxConfigBytes)
	}
	return b, nil
}

// Digest is the SHA-256 of a config file's bytes, lowercase hex.
//
// The collector reports it in every heartbeat so the control plane can show the
// customer which scope their collector is actually enforcing. A change is an
// audit event: a scope file edited on the host without anyone knowing is exactly
// the drift this makes visible.
func Digest(b []byte) string {
	sum := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(sum[:])
}
