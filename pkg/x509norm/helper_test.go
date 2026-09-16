package x509norm_test

import (
	"testing"

	"github.com/certwatch/certwatch/test/corpus"
)

func corpusLoad(t *testing.T) ([]corpus.Entry, []corpus.Entry, error) {
	t.Helper()
	return corpus.Load()
}
