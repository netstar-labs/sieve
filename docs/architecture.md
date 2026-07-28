# Architecture

## Data model

The authoritative dataset is a sorted, deduped set of **full SHA-256 hashes** of
canonical URL expressions. Two structures are *derived* from it at load for speed:

- a sorted `[]uint32` **prefix `Set`** (the first 4 bytes of each hash) — the
  cache-friendly binary-search prefilter;
- a **cuckoo filter** over those prefixes — a compact "definitely-not / maybe"
  gate that discards true negatives before the `Set` is touched.

Shipping the full hashes (not just prefixes) is the deliberate choice that makes a
match **exact**: a surviving prefix is confirmed against the full-hash tier, so
there is no prefix-collision uncertainty and no remote confirm step.

## Query path

```
raw URL ─▶ Canon (injected) ─▶ Expand ─▶ for each expression:
             HashURL ─▶ Prefix
               ├─ cuckoo.contains?  no ─▶ skip (certain negative)
               ├─ Set.Contains?     no ─▶ skip (filter false positive)
               └─ full hash in confirm tier?  yes ─▶ Listed   no ─▶ keep scanning
           ─▶ Clean
```

The cuckoo filter is a **latency optimization, never a correctness input**: it has
no false negatives (a listed prefix always answers "maybe"), and a false positive
merely falls through to the authoritative `Set`. If insertion ever overflows, the
filter *saturates* (answers "maybe" for everything), which preserves correctness
at the cost of always consulting the `Set`.

## Expansion

One canonical key is expanded into ≤30 expressions — up to 5 host suffixes
(exact host + last-4…last-2 label suffixes; IPs are not suffixed) × up to 6 path
prefixes (exact ±query, then `/`, `/a/`, `/a/b/`, `/a/b/c/`). Listing granularity
is the publisher's: an exact URL, a directory, or a whole host (`host/`).

## Storage & concurrency

The live dataset is an immutable `index` (Set + filter + confirm tier + header)
behind an `atomic.Pointer`. Readers `Load` it lock-free; an update builds a fresh
index and `Store`s it in one word-sized write. A concurrent lookup always sees one
complete index — the old or the new — never a torn one. This is exercised under
`-race`.

## Distribution

- **Snapshot** — a stamped header (version, canon **profile**, **expander**, **IDNA**
  mode, epoch, count, dataset hash) followed by the sorted full hashes. The
  decoder is **attacker-facing**: bounded allocation (a lying count cannot
  pre-allocate — the body grows only with bytes actually read), strictly-increasing
  validation (catches unsorted and duplicate), and a dataset-hash checksum. A
  malformed stream returns an error, never a panic or OOM. Continuously fuzzed.
- **Delta** — `adds`/`removes` anchored at both ends: it refuses the wrong base and
  refuses a result that does not hash to the declared target (self-verifying
  convergence). Deletion is why the prefilter is a cuckoo, not a Bloom, filter.
- **Fetch** — HTTPS with an `io.LimitedReader` body cap (no OOM from a hostile
  feed) and SPKI SHA-256 pinning of the leaf certificate (the pin replaces chain
  trust). These live in the transport because the dataset format cannot provide
  them.

## The canonicalization seam & IDNA

Canonicalization is injected (`Canon func(string) (string, bool)`), so sieve builds
and tests without coupling to the canonicalization contract's version. Because
IDNA mapping changes which canonical host a Unicode input produces, the **IDNA mode
is stamped in the snapshot header** alongside the profile and expander — build and
query must pin the same one, or Unicode-host hashes silently won't line up (a
blocklist false-negative). The stamps travel on every `Match` so a mismatch is
observable.

## Trade-offs recorded

- **Full hashes over gap-encoded prefixes.** Once full hashes ship (for exactness),
  28 of every 32 bytes are incompressible, so gap-encoding buys little — compression
  is left to the transport (gzip). Storing hashes raw also keeps the attacker-facing
  decoder minimal.
- **Delta rebuilds the derived index.** v0.1.0 applies a delta to the hash set and
  rebuilds the Set + filter; incremental filter mutation is a later optimization.
- **`ConfirmNeeded`** is defined for a future prefix-only (space-constrained)
  snapshot mode; the default full-hash snapshot resolves every hit to `Listed`/`Clean`.
