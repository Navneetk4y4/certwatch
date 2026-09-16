package main

import (
	"fmt"
	"net/netip"
	"path/filepath"
	"strconv"
	"strings"
)

// scopeDocument is certscan's minimal reader for scope.yaml.
//
// certscan deliberately does NOT import internal/scopecfg: CI-009 enforces that
// the open-source scanner depends on pkg/ only, so the open-source boundary is
// a property of the build rather than a policy. The cost is this small duplicate
// reader; the benefit is that the published binary provably contains no
// commercial code.
//
// It is a line-oriented subset reader rather than a YAML parser, which also
// means the published scanner has ZERO runtime dependencies.
type scopeDocument struct {
	cidrs       []netip.Prefix
	dirs        []string
	ports       []int
	rate        int
	concurrency int
}

func parseScopeDocument(raw []byte) (*scopeDocument, error) {
	sc := &scopeDocument{}
	var section string
	sawVersion := false

	for n, line := range strings.Split(string(raw), "\n") {
		lineNo := n + 1
		t := strings.TrimRight(line, " \t\r")
		if t == "" || strings.HasPrefix(strings.TrimSpace(t), "#") {
			continue
		}
		trimmed := strings.TrimSpace(t)

		if strings.HasPrefix(trimmed, "- ") {
			val := strings.Trim(strings.TrimSpace(trimmed[2:]), `"'`)
			switch section {
			case "cidrs":
				p, err := netip.ParsePrefix(val)
				if err != nil {
					return nil, fmt.Errorf("scope line %d: %q is not a CIDR", lineNo, val)
				}
				sc.cidrs = append(sc.cidrs, p.Masked())
			case "certificate_directories":
				d, err := absDir(val)
				if err != nil {
					return nil, fmt.Errorf("scope line %d: %w", lineNo, err)
				}
				sc.dirs = append(sc.dirs, d)
			case "ports":
				p, err := strconv.Atoi(val)
				if err != nil || p < 1 || p > 65535 {
					return nil, fmt.Errorf("scope line %d: %q is not a valid port", lineNo, val)
				}
				sc.ports = append(sc.ports, p)
			}
			continue
		}

		key, value, found := strings.Cut(trimmed, ":")
		if !found {
			return nil, fmt.Errorf("scope line %d: cannot parse %q", lineNo, trimmed)
		}
		key = strings.TrimSpace(key)
		value = strings.TrimSpace(value)
		section = key

		switch key {
		case "version":
			sawVersion = true
			if value != "1" {
				return nil, fmt.Errorf("scope: unsupported version %q (want 1)", value)
			}
		case "rate_limit_per_second":
			n, err := strconv.Atoi(value)
			if err != nil {
				return nil, fmt.Errorf("scope line %d: rate_limit_per_second must be a number", lineNo)
			}
			sc.rate = n
		case "max_concurrency":
			n, err := strconv.Atoi(value)
			if err != nil {
				return nil, fmt.Errorf("scope line %d: max_concurrency must be a number", lineNo)
			}
			sc.concurrency = n
		case "cidrs", "certificate_directories", "ports", "exclude_cidrs", "exclude_hosts":
			if value != "" && value != "[]" {
				// Inline list form: ports: [443, 8443]
				inline := strings.Trim(value, "[]")
				for _, part := range strings.Split(inline, ",") {
					part = strings.Trim(strings.TrimSpace(part), `"'`)
					if part == "" {
						continue
					}
					switch key {
					case "ports":
						p, err := strconv.Atoi(part)
						if err != nil || p < 1 || p > 65535 {
							return nil, fmt.Errorf("scope line %d: %q is not a valid port", lineNo, part)
						}
						sc.ports = append(sc.ports, p)
					case "cidrs":
						p, err := netip.ParsePrefix(part)
						if err != nil {
							return nil, fmt.Errorf("scope line %d: %q is not a CIDR", lineNo, part)
						}
						sc.cidrs = append(sc.cidrs, p.Masked())
					case "certificate_directories":
						d, err := absDir(part)
						if err != nil {
							return nil, fmt.Errorf("scope line %d: %w", lineNo, err)
						}
						sc.dirs = append(sc.dirs, d)
					}
				}
				section = ""
			}
		default:
			return nil, fmt.Errorf("scope line %d: unknown field %q. "+
				"Unknown fields are refused so a misspelling cannot silently widen or narrow your scope", lineNo, key)
		}
	}
	if !sawVersion {
		return nil, fmt.Errorf("scope: missing `version: 1`")
	}
	return sc, nil
}

// absDir validates a directory path from configuration or a flag.
func absDir(d string) (string, error) {
	if strings.ContainsRune(d, 0) {
		return "", fmt.Errorf("path contains a NUL byte")
	}
	if strings.Contains(d, "..") {
		return "", fmt.Errorf("path %q contains a traversal sequence", d)
	}
	abs, err := filepath.Abs(d)
	if err != nil {
		return "", fmt.Errorf("path %q: %w", d, err)
	}
	clean := filepath.Clean(abs)
	for _, p := range []string{"/proc", "/sys", "/dev"} {
		if clean == p || strings.HasPrefix(clean, p+"/") {
			return "", fmt.Errorf("path %q is under a refused prefix", d)
		}
	}
	return clean, nil
}

func absPath(p string) (string, error) {
	if strings.ContainsRune(p, 0) {
		return "", fmt.Errorf("path contains a NUL byte")
	}
	return filepath.Abs(p)
}
