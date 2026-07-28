package sieve

import (
	"crypto/sha256"
	"encoding/binary"
)

// Hash is the SHA-256 of a canonical URL expression — the authoritative dataset
// entry. The dataset ships full hashes (not just prefixes) so a match is exact:
// there is no remote round-trip to confirm a prefix collision.
type Hash [32]byte

// HashURL hashes a canonical URL expression. The caller MUST have canonicalized
// (and expanded) the URL first — sieve keys on canonical bytes, so build and
// query have to agree on the canonicalization (see the snapshot header stamps).
func HashURL(expr string) Hash { return sha256.Sum256([]byte(expr)) }

// Prefix is the 4-byte big-endian head of a hash — the compact key of the
// prefilter [Set]. Many hashes may share a prefix; the full [Hash] disambiguates
// (~1-in-4-billion prefix collisions resolve against the confirm tier).
func Prefix(h Hash) uint32 { return binary.BigEndian.Uint32(h[:4]) }

// datasetHash is the identity of a sorted, deduped hash set: SHA-256 over the
// concatenated hashes in order. It pins a snapshot and anchors a delta's base and
// target, so an apply is self-verifying (the result must hash to the declared
// target) and a delta cannot be applied to the wrong base.
func datasetHash(sorted []Hash) [32]byte {
	h := sha256.New()
	for i := range sorted {
		h.Write(sorted[i][:])
	}
	return [32]byte(h.Sum(nil))
}
