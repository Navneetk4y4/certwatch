package safeio

import (
	"path/filepath"
	"strings"
	"testing"
)

// REGRESSION: ReadConfigFile must use an ALLOWLIST, not just a denylist.
//
// With a denylist alone it read /etc/shadow quite happily — no extension,
// therefore not denied — which made it a general file reader wearing a
// config-reader label. Found by adversarial review.
func TestReadConfigFileUsesAnAllowlist(t *testing.T) {
	dir := t.TempDir()

	allowed := []string{"scope.yaml", "scope.yml", "hosts.txt", "conf.json", "a.conf", "h.list"}
	for _, n := range allowed {
		p := filepath.Join(dir, n)
		writeFile(t, p, []byte("version: 1\n"))
		if _, err := ReadConfigFile(p); err != nil {
			t.Errorf("ReadConfigFile(%s) refused a legitimate config file: %v", n, err)
		}
	}

	refused := []string{"shadow", "passwd", "id_rsa", "server.key", "store.p12", "core.dump", "secrets.env"}
	for _, n := range refused {
		p := filepath.Join(dir, n)
		writeFile(t, p, []byte("root:$6$hash\n"))
		if _, err := ReadConfigFile(p); err == nil {
			t.Errorf("ReadConfigFile(%s) read a file it has no business reading", n)
		} else if !strings.Contains(err.Error(), "configuration") && !strings.Contains(err.Error(), "key") {
			t.Errorf("ReadConfigFile(%s) refused for an unclear reason: %v", n, err)
		}
	}
}
