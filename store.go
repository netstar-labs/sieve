package sieve

import (
	"bytes"
	"slices"
	"sync/atomic"
)

// index is the immutable, query-ready form of a snapshot: the derived prefilter
// (cuckoo + prefix [Set]) in front of the authoritative full-hash confirm tier,
// plus the header stamps. Built once, never mutated, swapped wholesale.
type index struct {
	header  Header
	set     *Set
	filter  *cuckoo
	confirm []Hash // the sorted full hashes — the exact confirm tier
}

func buildIndex(s *Snapshot) *index {
	set := NewSet(s.prefixes())
	filter := newCuckoo(set.Len())
	for _, p := range set.keysRef() {
		filter.add(p)
	}
	return &index{header: s.Header, set: set, filter: filter, confirm: s.Hashes}
}

// Store holds the live dataset behind an atomic pointer: readers load it
// lock-free, and an update swaps in a freshly built immutable index. A concurrent
// lookup during a swap always sees one complete index — the old or the new —
// never a half-built one.
type Store struct {
	cur atomic.Pointer[index]
}

// NewStore returns an empty store; every lookup is Clean until Install.
func NewStore() *Store { return &Store{} }

// Install builds the query index for snap and atomically swaps it in.
func (s *Store) Install(snap *Snapshot) { s.cur.Store(buildIndex(snap)) }

// ApplyDelta applies d to the current dataset and swaps in the result, leaving the
// current dataset untouched on any error (no current dataset, base mismatch, or
// failed convergence).
func (s *Store) ApplyDelta(d *Delta) error {
	idx := s.cur.Load()
	if idx == nil {
		return ErrBase
	}
	next, err := d.Apply(&Snapshot{Header: idx.header, Hashes: idx.confirm})
	if err != nil {
		return err
	}
	s.cur.Store(buildIndex(next))
	return nil
}

func (s *Store) current() *index { return s.cur.Load() }

// containsHash binary-searches the sorted confirm tier.
func containsHash(sorted []Hash, h Hash) bool {
	_, ok := slices.BinarySearchFunc(sorted, h, func(a, b Hash) int { return bytes.Compare(a[:], b[:]) })
	return ok
}
