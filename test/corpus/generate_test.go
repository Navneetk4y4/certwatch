package corpus

import "testing"

// The committed corpus must be present, large enough, and self-describing.
func TestCommittedCorpus(t *testing.T) {
	valid, malformed, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if len(valid) < 500 {
		t.Fatalf("corpus has %d valid entries, want at least 500 (run `make corpus`)", len(valid))
	}
	if len(malformed) < 10 {
		t.Fatalf("corpus has %d malformed entries, want at least 10", len(malformed))
	}
	seen := map[string]bool{}
	for _, e := range append(append([]Entry{}, valid...), malformed...) {
		if seen[e.Name] {
			t.Fatalf("duplicate corpus entry name %q", e.Name)
		}
		seen[e.Name] = true
		if e.Exercises == "" {
			t.Fatalf("entry %q does not say what it exercises", e.Name)
		}
	}
	t.Logf("corpus: %d valid, %d malformed", len(valid), len(malformed))
}

// Loading twice must give identical bytes. This is the property that makes a
// parse-rate change attributable to the parser.
func TestCorpusLoadIsStable(t *testing.T) {
	a, am, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	b, bm, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if len(a) != len(b) || len(am) != len(bm) {
		t.Fatal("corpus size changed between loads")
	}
	for i := range a {
		if a[i].Name != b[i].Name || string(a[i].DER) != string(b[i].DER) {
			t.Fatalf("entry %d differs between loads", i)
		}
	}
}
