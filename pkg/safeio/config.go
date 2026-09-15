package safeio

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"syscall"
)

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
	if ext := lowerExt(path); deniedExtensions[ext] {
		return nil, fmt.Errorf("safeio: refusing to open %q: extension %s is a key or keystore format", path, ext)
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
