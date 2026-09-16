package main

import (
	"fmt"
	"strings"

	"github.com/certwatch/certwatch/pkg/safeio"
)

// MaxHostsFileEntries bounds a hosts file.
const MaxHostsFileEntries = 50_000

// readHostsFile reads one hostname per line.
//
// Read through safeio so all file access in the binary stays inside the
// boundary. safeio.ReadConfigFile refuses symlinks, oversized files and any
// path with a key or keystore extension.
func readHostsFile(path string) ([]string, error) {
	abs, err := absPath(path)
	if err != nil {
		return nil, err
	}
	raw, err := safeio.ReadConfigFile(abs)
	if err != nil {
		return nil, fmt.Errorf("reading hosts file: %w", err)
	}
	var out []string
	for _, line := range strings.Split(string(raw), "\n") {
		h := strings.TrimSpace(line)
		if h == "" || strings.HasPrefix(h, "#") {
			continue
		}
		if len(out) >= MaxHostsFileEntries {
			return nil, fmt.Errorf("hosts file has more than %d entries", MaxHostsFileEntries)
		}
		out = append(out, h)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("hosts file %s contained no hostnames", path)
	}
	return out, nil
}
