package corpus

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
)

// The corpus is GENERATED ONCE AND COMMITTED, not regenerated per run.
//
// Go deliberately randomises key generation (crypto/internal/randutil
// MaybeReadByte reads a byte with ~50% probability) specifically to stop
// programs depending on deterministic output from a fixed reader. That makes
// regenerate-per-run corpora non-reproducible, and a non-reproducible corpus
// means a parse-rate regression cannot be attributed to a code change rather
// than to a different sample.
//
// Committing the bytes makes the corpus a fixed fixture: if the pass rate
// moves, the parser changed.
//
// Regenerate deliberately with:  make corpus

const corpusFile = "corpus.json"

type fileEntry struct {
	Name            string `json:"name"`
	DERBase64       string `json:"der"`
	ExpectParseable bool   `json:"expect_parseable"`
	Exercises       string `json:"exercises"`
	Malformed       bool   `json:"malformed,omitempty"`
}

// Load reads the committed corpus.
func Load() ([]Entry, []Entry, error) {
	path := filepath.Join(dir(), "testdata", corpusFile)
	b, err := os.ReadFile(path) //nolint:gosec // test fixture, not collector code
	if err != nil {
		return nil, nil, fmt.Errorf("corpus: %w (run `make corpus` to generate it)", err)
	}
	var fes []fileEntry
	if err := json.Unmarshal(b, &fes); err != nil {
		return nil, nil, fmt.Errorf("corpus: %w", err)
	}
	var valid, malformed []Entry
	for _, fe := range fes {
		der, err := base64.StdEncoding.DecodeString(fe.DERBase64)
		if err != nil {
			return nil, nil, fmt.Errorf("corpus: entry %q: %w", fe.Name, err)
		}
		e := Entry{Name: fe.Name, DER: der, ExpectParseable: fe.ExpectParseable, Exercises: fe.Exercises}
		if fe.Malformed {
			malformed = append(malformed, e)
		} else {
			valid = append(valid, e)
		}
	}
	return valid, malformed, nil
}

// Write serialises a generated corpus to the committed file.
func Write(path string, valid, malformed []Entry) error {
	fes := make([]fileEntry, 0, len(valid)+len(malformed))
	for _, e := range valid {
		fes = append(fes, fileEntry{e.Name, base64.StdEncoding.EncodeToString(e.DER), e.ExpectParseable, e.Exercises, false})
	}
	for _, e := range malformed {
		fes = append(fes, fileEntry{e.Name, base64.StdEncoding.EncodeToString(e.DER), false, e.Exercises, true})
	}
	b, err := json.MarshalIndent(fes, "", " ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, b, 0o644) //nolint:gosec // test fixture
}

func dir() string {
	_, f, _, _ := runtime.Caller(0)
	return filepath.Dir(f)
}
