// Command gencorpus regenerates the committed certificate corpus.
//
// Run deliberately (`make corpus`), never automatically: the whole point of
// committing the corpus is that it does not change underneath a parse-rate
// measurement.
package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/certwatch/certwatch/test/corpus"
)

func main() {
	n := flag.Int("n", 460, "routine certificates to add on top of the edge cases")
	out := flag.String("out", "test/corpus/testdata/corpus.json", "output path")
	flag.Parse()

	valid, err := corpus.Generate(*n)
	if err != nil {
		fmt.Fprintln(os.Stderr, "gencorpus:", err)
		os.Exit(1)
	}
	malformed := corpus.Malformed()
	if err := corpus.Write(*out, valid, malformed); err != nil {
		fmt.Fprintln(os.Stderr, "gencorpus:", err)
		os.Exit(1)
	}
	fmt.Printf("gencorpus: wrote %d valid + %d malformed entries to %s\n", len(valid), len(malformed), *out)
}
