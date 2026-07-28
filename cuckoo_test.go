package sieve

import "testing"

// distinct maps an index to a distinct uint32 (multiply by an odd constant is a
// bijection mod 2^32, and mix is a bijection, so all outputs are distinct).
func distinct(i int) uint32 { return mix(uint32(i) * 2654435761) }

// The load-bearing invariant: a prefix that was added must always answer "maybe".
func TestCuckooNoFalseNegative(t *testing.T) {
	const n = 20000
	c := newCuckoo(n)
	for i := 0; i < n; i++ {
		c.add(distinct(i))
	}
	for i := 0; i < n; i++ {
		if !c.contains(distinct(i)) {
			t.Fatalf("false negative for item %d (saturated=%v)", i, c.saturated)
		}
	}
}

func TestCuckooLowFalsePositive(t *testing.T) {
	const n = 20000
	c := newCuckoo(n)
	member := make(map[uint32]bool, n)
	for i := 0; i < n; i++ {
		x := distinct(i)
		c.add(x)
		member[x] = true
	}
	if c.saturated {
		t.Fatal("filter saturated at ~50% target load")
	}
	fp, tries := 0, 0
	for i := n; i < n+100000; i++ {
		x := distinct(i)
		if member[x] {
			continue
		}
		tries++
		if c.contains(x) {
			fp++
		}
	}
	if rate := float64(fp) / float64(tries); rate > 0.01 {
		t.Errorf("false-positive rate %.4f exceeds 1%%", rate)
	}
}

func TestCuckooDelete(t *testing.T) {
	c := newCuckoo(100)
	x := uint32(0xDEADBEEF)
	c.add(x)
	if !c.contains(x) {
		t.Fatal("contains false right after add")
	}
	if !c.delete(x) {
		t.Fatal("delete returned false for a present item")
	}
	if c.contains(x) {
		t.Error("still present after delete (single item, no collision)")
	}
	if c.delete(x) {
		t.Error("second delete of an absent item returned true")
	}
}

// Even when insertion overflows and the filter saturates, the no-false-negative
// guarantee must hold (saturated => always maybe).
func TestCuckooSaturateKeepsNoFalseNegative(t *testing.T) {
	c := newCuckoo(4) // deliberately tiny
	const n = 5000
	for i := 0; i < n; i++ {
		c.add(distinct(i))
	}
	for i := 0; i < n; i++ {
		if !c.contains(distinct(i)) {
			t.Fatalf("false negative for item %d after saturation", i)
		}
	}
}
