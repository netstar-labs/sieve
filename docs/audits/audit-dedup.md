# Audit — duplication / dedup (auditor B), 2026-09-29 pre-public pass

Scope: owned code (same as `audit-correctness.md`). Builds on the 2026-07
audit's already-applied dedup (a single `compareHash`; a generic
`fetchDecode[T]`) — not re-litigated.

## Fixed in this pass

**The fixed-width wire-field decode primitive** — `Decode` and `DecodeDelta`
each repeated the identical "`io.ReadFull(br, buf)`; on any error return
`ErrTruncated`" idiom for every fixed-size field, and `Decode` hand-rolled
the exact 4-byte-read+`BigEndian.Uint32` logic `DecodeDelta` had already
factored into `readCount` — the prior audit's dedup pass caught this shape
in `delta.go` but didn't reach across to the matching field in
`snapshot.go`. Extracted `readExact`/`readUint32`/`readUint64` (shared by
both decoders); `readCount` deleted, its 2 call sites repointed. Magic,
version-check branching, and the differing wrap of `ErrVersion`
deliberately left alone — those genuinely diverge between the two decoders
and aren't part of this dedup.

**`diff()`'s adds/removes computation** — replaced two `map[Hash]bool` sets
with a linear merge over the two sorted `Hashes` slices (the documented
`Snapshot` invariant), matching the shape of problem a two-pointer merge
solves in one pass with zero hash-map allocation. Verified equivalent via
200,000 randomized trials before applying. Real savings for `diff`
specifically: a batch operation on datasets the header allows up to 2^30
entries in.

## Applied earlier in this session (same finding, cross-referenced)

The CLI's args-vs-stdin dispatch pattern this repo's sibling packages
(unmask) had — checked here too, not present: `app/sieve/main.go`'s five
subcommands each have distinct, non-duplicated flag sets and bodies; no
cluster like unmask's `forEachLabel` exists in this file.

## Considered and NOT recommended

- **`Client.maxBody()`/`timeout()`** ("field-or-default" pattern, 2
  occurrences) — looks swappable for stdlib `cmp.Or`, but this is a subtle
  behavior change, not a safe dedup: the current code treats a negative
  field as "unset → default" (`> 0` guard), while `cmp.Or` treats any
  non-zero value (including negative) as "set." Nothing validates
  `MaxBody`/`Timeout` can't be negative, so the swap would silently change
  behavior for that input. Kept.
- **`hostVariants`/`pathVariants`'s capped-dedup-append shapes** (before
  this pass's bounded-scan rewrite) — 2 occurrences, different control-flow
  shapes and different caps; a generic accumulator would obscure the 30-vs-6
  semantics for marginal savings. Moot now — the bounded-scan rewrite
  (`audit-correctness.md` finding 1) replaced both bodies entirely.
- **`tryPut`/`hasFP`** (cuckoo.go) — both scan a bucket's 4 slots but one
  writes-on-first-empty, the other reads-on-match; different semantics on
  the package's explicitly-documented latency-critical hot path. Collapsing
  risks de-optimizing code whose whole purpose is speed. Not worth ~5 LOC.
- **`Delta.Apply`'s hash-set union vs. `main.go` `diff()`'s two membership
  maps** — superficially similar ("map built from a `[]Hash`") but solve
  different problems (adds-win-over-removes union vs. two-way set
  difference) in two different packages. Not real duplication.
- **`scriptRange`-shaped generator/generated-code pairing** — not
  applicable to this repo (that was a unmask finding); no analog here.
