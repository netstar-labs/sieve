package sieve

import (
	"fmt"
	"slices"
	"strings"
)

// hashN returns n distinct hashes for building test datasets.
func hashN(n int) []Hash {
	hs := make([]Hash, n)
	for i := range hs {
		hs[i] = HashURL(fmt.Sprintf("expr-%d", i))
	}
	return hs
}

// lc is a trivial canonicalizer (lowercase) for matcher tests.
func lc(u string) (string, bool) { return strings.ToLower(u), true }

// listing builds a snapshot whose dataset is exactly the given canonical
// expressions (the exact-coverage policy: the publisher owns granularity).
func listing(exprs ...string) *Snapshot {
	hs := make([]Hash, len(exprs))
	for i, e := range exprs {
		hs[i] = HashURL(e)
	}
	return NewSnapshot("url/1", "expr/1", "idna:15.0.0", 1, hs)
}

func cloneBytes(b []byte) []byte { return slices.Clone(b) }
