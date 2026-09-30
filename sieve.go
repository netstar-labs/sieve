// Package sieve is a standalone, partner-facing URL-reputation matcher: it answers
// "is this URL in our dataset?" against a netstar dataset distributed as an
// immutable snapshot plus self-verifying deltas — offline, exact, and lock-free.
//
// A query URL is canonicalized (an injected [Canon] seam), expanded into ≤30
// host-suffix × path-prefix expressions ([Expand]), and each is SHA-256 hashed.
// A compact cuckoo prefilter and a sorted uint32 prefix [Set] discard true
// negatives fast; a surviving prefix is confirmed against a sorted full-hash tier,
// so a match is exact (no ~1-in-4-billion prefix collision, and no remote
// round-trip). The live dataset sits behind an atomic pointer in a store for
// lock-free reads and whole-snapshot swaps.
//
// sieve is the lookup side of a two-part contract: canonicalization ("one URL →
// one key") is a separate concern, injected here so build and query agree on it.
// The snapshot header stamps the canonicalization profile, expander, and IDNA
// mode — build and query MUST match, or Unicode-host hashes silently won't line
// up (a false-negative). sieve has zero external dependencies.
package sieve

// Canon is the injected canonicalization seam: a raw URL to its uniform lookup
// key, plus ok=false when the input cannot be canonicalized. Production wires the
// netstar canonicalizer here; keeping it injected lets sieve build, test, and ship
// without coupling to the canonicalization contract's version.
type Canon func(rawURL string) (canonical string, ok bool)

// Verdict is the outcome of a [Matcher.Lookup].
type Verdict uint8

const (
	// Clean: no expanded expression is in the dataset.
	Clean Verdict = iota
	// Listed: an expression matched a full hash — authoritative.
	Listed
)

func (v Verdict) String() string {
	switch v {
	case Listed:
		return "listed"
	default:
		return "clean"
	}
}

// Match is a lookup result: the verdict, the expression and prefix that hit (empty
// / 0 when Clean), and the dataset stamps the answer was produced under — a rich
// result rather than a bare bool, so the caller can log provenance and detect a
// build/query canonicalization mismatch.
type Match struct {
	Verdict    Verdict
	Prefix     uint32
	Expression string
	Profile    string
	Expander   string
	IDNA       string
}

// Listed reports the common case succinctly.
func (m Match) IsListed() bool { return m.Verdict == Listed }

// Matcher answers reputation lookups against a live store, canonicalizing and
// expanding each URL first. Safe for concurrent use; reads are lock-free.
type Matcher struct {
	store *store
	canon Canon
}

// New returns a matcher with an empty store. Wire canon to the same canonicalizer
// the dataset was built under (see the header stamps); a nil canon treats the
// input as already canonical.
func New(canon Canon) *Matcher { return &Matcher{store: newStore(), canon: canon} }

// Install swaps in a new dataset snapshot.
func (m *Matcher) Install(snap *Snapshot) { m.store.Install(snap) }

// ApplyDelta evolves the current dataset by a delta (see store.ApplyDelta).
func (m *Matcher) ApplyDelta(d *Delta) error { return m.store.ApplyDelta(d) }

// Lookup canonicalizes, expands, and tests rawURL against the current dataset.
func (m *Matcher) Lookup(rawURL string) Match {
	idx := m.store.current()
	if idx == nil {
		return Match{Verdict: Clean}
	}
	canonical := rawURL
	if m.canon != nil {
		c, ok := m.canon(rawURL)
		if !ok {
			return Match{Verdict: Clean} // uncanonicalizable input cannot be in the dataset
		}
		canonical = c
	}
	stamp := func(v Verdict, p uint32, e string) Match {
		return Match{Verdict: v, Prefix: p, Expression: e,
			Profile: idx.header.Profile, Expander: idx.header.Expander, IDNA: idx.header.IDNA}
	}
	for _, expr := range Expand(canonical) {
		h := HashURL(expr)
		p := Prefix(h)
		if !idx.filter.contains(p) {
			continue // certain negative — skip the Set
		}
		if !idx.set.Contains(p) {
			continue // prefilter false positive
		}
		if containsHash(idx.confirm, h) {
			return stamp(Listed, p, expr)
		}
		// prefix collision (full-hash miss): keep scanning the other expressions
	}
	return stamp(Clean, 0, "")
}
