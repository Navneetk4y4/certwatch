package scan

import (
	"fmt"
	"net/netip"
)

// blockedPrefixes are refused UNCONDITIONALLY — even when a customer explicitly
// lists them in scope.yaml.
//
// This is the one place the customer's own configuration does not win, and the
// reason is that these addresses are not really "theirs": the cloud metadata
// endpoints hand out credentials, and loopback/link-local reach services that
// assume the caller is the host itself. A scanner that can be pointed at
// 169.254.169.254 is a credential-theft primitive with a business model
// (threat T3).
//
// A customer who genuinely wants to scan their own loopback can run the scanner
// on that host against a real address.
var blockedPrefixes = []netip.Prefix{
	// IPv4
	netip.MustParsePrefix("0.0.0.0/8"),      // "this network"
	netip.MustParsePrefix("127.0.0.0/8"),    // loopback
	netip.MustParsePrefix("169.254.0.0/16"), // link-local, includes 169.254.169.254 (AWS/Azure IMDS)
	netip.MustParsePrefix("224.0.0.0/4"),    // multicast
	netip.MustParsePrefix("240.0.0.0/4"),    // reserved
	netip.MustParsePrefix("255.255.255.255/32"),
	// IPv6
	netip.MustParsePrefix("::/128"),        // unspecified
	netip.MustParsePrefix("::1/128"),       // loopback
	netip.MustParsePrefix("fe80::/10"),     // link-local
	netip.MustParsePrefix("ff00::/8"),      // multicast
	netip.MustParsePrefix("fd00:ec2::/64"), // AWS IMDS over IPv6
	netip.MustParsePrefix("100::/64"),      // discard-only
}

// blockedExact are single addresses that fall outside the prefixes above or
// deserve to be named explicitly so a reviewer can see them.
var blockedExact = []netip.Addr{
	netip.MustParseAddr("169.254.169.254"), // AWS, Azure, DigitalOcean, Oracle IMDS
	netip.MustParseAddr("169.254.170.2"),   // ECS task metadata
	netip.MustParseAddr("100.100.100.100"), // Alibaba Cloud metadata
	netip.MustParseAddr("192.0.0.192"),     // Oracle Cloud legacy metadata
	netip.MustParseAddr("fd00:ec2::254"),   // AWS IMDSv6
}

// blockedNames are hostnames that resolve to metadata services. They are checked
// by name as well as by resolved address, because a split-horizon resolver can
// return an in-scope-looking address for them.
var blockedNames = map[string]bool{
	"metadata.google.internal": true,
	"metadata.goog":            true,
	"instance-data":            true,
}

// AddrBlocked reports whether an address may never be connected to, and why.
//
// This function is deliberately total and deliberately boring: there is no
// configuration, no override, and no caller-supplied allowance.
func AddrBlocked(a netip.Addr) (bool, string) {
	a = a.Unmap()
	if !a.IsValid() {
		return true, "invalid address"
	}
	for _, x := range blockedExact {
		if a == x.Unmap() {
			return true, fmt.Sprintf("%s is a cloud instance-metadata endpoint", a)
		}
	}
	for _, p := range blockedPrefixes {
		if p.Contains(a) {
			return true, fmt.Sprintf("%s is inside the permanently blocked range %s", a, p)
		}
	}
	// Belt and braces: netip's own classification, in case a range above is
	// ever edited incorrectly.
	switch {
	case a.IsLoopback():
		return true, "loopback address"
	case a.IsLinkLocalUnicast(), a.IsLinkLocalMulticast():
		return true, "link-local address"
	case a.IsMulticast():
		return true, "multicast address"
	case a.IsUnspecified():
		return true, "unspecified address"
	case a.IsInterfaceLocalMulticast():
		return true, "interface-local multicast address"
	}
	return false, ""
}

// NameBlocked reports whether a hostname is a known metadata name.
func NameBlocked(host string) (bool, string) {
	h := normaliseHost(host)
	if blockedNames[h] {
		return true, h + " is a cloud instance-metadata hostname"
	}
	return false, ""
}

func normaliseHost(h string) string {
	out := make([]byte, 0, len(h))
	for i := 0; i < len(h); i++ {
		c := h[i]
		if c >= 'A' && c <= 'Z' {
			c += 'a' - 'A'
		}
		out = append(out, c)
	}
	s := string(out)
	for len(s) > 0 && s[len(s)-1] == '.' {
		s = s[:len(s)-1]
	}
	return s
}
