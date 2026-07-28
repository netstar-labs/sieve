package sieve

const (
	slotsPerBucket = 4
	maxKicks       = 500
)

// cuckoo is a cuckoo filter over uint32 prefixes: a compact "definitely-not /
// maybe" prefilter with NO false negatives — a prefix that was added always
// answers maybe. It fronts the authoritative [Set] so the miss-dominated query
// path skips the binary search on a true negative; a false positive merely falls
// through to the Set, so the filter is a latency win, never a correctness input.
// Unlike a Bloom filter it supports delete, which is why the dataset can evolve
// by delta rather than only by full rebuild.
//
// Every stored fingerprint lives in one of its item's two candidate buckets
// (the eviction walk preserves that), so checking both candidates can never miss
// a present item. If an insert cannot find room after maxKicks the filter
// degrades to "saturated" — contains always returns maybe — which keeps the
// no-false-negative guarantee at the cost of always consulting the Set.
type cuckoo struct {
	buckets   [][slotsPerBucket]uint16 // 0 = empty slot; fingerprints are nonzero
	mask      uint32                   // len(buckets)-1; len(buckets) is a power of two
	saturated bool
}

// newCuckoo sizes for ~50% load: buckets ≈ capacity/2 rounded up to a power of
// two (so the alt-index XOR stays in range), and at least one bucket.
func newCuckoo(capacity int) *cuckoo {
	need := capacity/2 + 1
	n := 1
	for n < need {
		n <<= 1
	}
	return &cuckoo{buckets: make([][slotsPerBucket]uint16, n), mask: uint32(n - 1)}
}

// mix is a cheap, well-distributed integer finalizer (splittable-style), used for
// both the primary bucket index and the fingerprint.
func mix(x uint32) uint32 {
	x ^= x >> 16
	x *= 0x7feb352d
	x ^= x >> 15
	x *= 0x846ca68b
	x ^= x >> 16
	return x
}

// fingerprint is a nonzero 16-bit tag of x (0 is reserved for the empty slot).
func fingerprint(x uint32) uint16 {
	f := uint16(mix(x) >> 16)
	if f == 0 {
		f = 1
	}
	return f
}

func (c *cuckoo) i1(x uint32) uint32 { return mix(x) & c.mask }

// alt is the second candidate bucket, i XOR (mix(fingerprint) & mask). It is an
// involution — alt(alt(i,f),f) == i — because mask is a power-of-two boundary, so
// either candidate recovers the other from the stored fingerprint alone.
func (c *cuckoo) alt(i uint32, f uint16) uint32 { return i ^ (mix(uint32(f)) & c.mask) }

func (c *cuckoo) add(x uint32) {
	if c.saturated {
		return
	}
	f := fingerprint(x)
	i := c.i1(x)
	if c.tryPut(i, f) || c.tryPut(c.alt(i, f), f) {
		return
	}
	// both candidate buckets full: evict-and-reinsert (deterministic walk from x
	// so a rebuild is reproducible).
	j := i
	if x&1 == 1 {
		j = c.alt(i, f)
	}
	for k := 0; k < maxKicks; k++ {
		slot := int(mix(uint32(f)^j^uint32(k)) & (slotsPerBucket - 1))
		f, c.buckets[j][slot] = c.buckets[j][slot], f
		j = c.alt(j, f)
		if c.tryPut(j, f) {
			return
		}
	}
	c.saturated = true // no room -> degrade to always-maybe (Set stays authoritative)
}

func (c *cuckoo) tryPut(i uint32, f uint16) bool {
	b := &c.buckets[i]
	for s := range b {
		if b[s] == 0 {
			b[s] = f
			return true
		}
	}
	return false
}

func (c *cuckoo) contains(x uint32) bool {
	if c.saturated {
		return true
	}
	f := fingerprint(x)
	i := c.i1(x)
	return c.hasFP(i, f) || c.hasFP(c.alt(i, f), f)
}

func (c *cuckoo) hasFP(i uint32, f uint16) bool {
	b := &c.buckets[i]
	for s := range b {
		if b[s] == f {
			return true
		}
	}
	return false
}

// delete removes one occurrence of x's fingerprint. Like any cuckoo filter it may
// remove the slot of a DIFFERENT item that shares both fingerprint and bucket, so
// only delete items known to have been added; the Store rebuilds the index from
// the authoritative hash set on a delta rather than relying on incremental delete.
func (c *cuckoo) delete(x uint32) bool {
	if c.saturated {
		return false
	}
	f := fingerprint(x)
	i := c.i1(x)
	return c.removeFP(i, f) || c.removeFP(c.alt(i, f), f)
}

func (c *cuckoo) removeFP(i uint32, f uint16) bool {
	b := &c.buckets[i]
	for s := range b {
		if b[s] == f {
			b[s] = 0
			return true
		}
	}
	return false
}
