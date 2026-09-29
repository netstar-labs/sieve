package sieve

import (
	"slices"
	"testing"
)

func TestSetSortsAndDedupes(t *testing.T) {
	s := NewSet([]uint32{5, 1, 5, 3, 1, 3})
	if got := s.keysRef(); !slices.Equal(got, []uint32{1, 3, 5}) {
		t.Fatalf("keys = %v, want [1 3 5]", got)
	}
	if s.Len() != 3 {
		t.Fatalf("Len = %d, want 3", s.Len())
	}
}

func TestSetContains(t *testing.T) {
	s := NewSet([]uint32{10, 20, 30})
	for _, k := range []uint32{10, 20, 30} {
		if !s.Contains(k) {
			t.Errorf("Contains(%d) = false, want true", k)
		}
	}
	for _, k := range []uint32{0, 15, 31, ^uint32(0)} {
		if s.Contains(k) {
			t.Errorf("Contains(%d) = true, want false", k)
		}
	}
}

func TestSetClonesInput(t *testing.T) {
	in := []uint32{3, 1, 2}
	s := NewSet(in)
	in[0] = 99
	if s.Contains(99) {
		t.Error("NewSet retained/aliased the caller's slice")
	}
}
