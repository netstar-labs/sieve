package sieve

import (
	"crypto/sha256"
	"encoding/binary"
	"slices"
)

// Set is the prefilter index: a sorted, deduped []uint32 of hash prefixes with
// O(log n) membership. It is the load-bearing primitive — the fast, cache-friendly
// first authoritative check in front of the full-hash confirm tier. A prefix hit
// is only "maybe listed" (prefixes collide); the confirm tier decides.
type Set struct {
	keys []uint32 // sorted ascending, no duplicates
}

// NewSet builds a Set from arbitrary prefixes: it copies, sorts, and dedupes, so
// the caller's slice is never retained or mutated.
func NewSet(prefixes []uint32) *Set {
	keys := slices.Clone(prefixes)
	slices.Sort(keys)
	keys = slices.Compact(keys)
	return &Set{keys: keys}
}

// Contains reports whether prefix p is in the set (binary search).
func (s *Set) Contains(p uint32) bool {
	_, ok := slices.BinarySearch(s.keys, p)
	return ok
}

// Len is the number of distinct prefixes.
func (s *Set) Len() int { return len(s.keys) }

// keysRef returns the internal slice for read-only iteration (encode/build). Not
// exported: callers must not mutate the sorted invariant.
func (s *Set) keysRef() []uint32 { return s.keys }

// Hash is the identity of the prefix set: SHA-256 over the sorted prefixes. This
// is the prefix-index hash, distinct from a snapshot's dataset hash (which covers
// the full hashes); it exists so the prefilter itself is content-addressable.
func (s *Set) Hash() [32]byte {
	h := sha256.New()
	var b [4]byte
	for _, k := range s.keys {
		binary.BigEndian.PutUint32(b[:], k)
		h.Write(b[:])
	}
	return [32]byte(h.Sum(nil))
}
