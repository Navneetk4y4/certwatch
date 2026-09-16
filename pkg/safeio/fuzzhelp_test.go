package safeio

import (
	"os"
	"testing"
)

func writeFileRaw(t *testing.T, path string, b []byte) {
	t.Helper()
	if err := os.WriteFile(path, b, 0o644); err != nil {
		t.Fatal(err)
	}
}
