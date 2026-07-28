# sieve — torture-chamber audit findings

Four-dimension adversarial audit (simpler · dedup · correctness+security · doc-drift) with
an independent-skeptic refutation pass, 2026-07. **12 CONFIRMED · 0 PLAUSIBLE · 8 REFUTED.**
All CONFIRMED items applied in the follow-up fix commit; re-validated (build/vet/staticcheck/
deadcode/gofmt clean, `-race`, fuzz re-soak). `*` = failure reproduced against a copy.

## CONFIRMED — fixed

### SECURITY — fetch had no timeout (slowloris DoS) `*`
`fetch.go` — the body was byte-capped (`io.LimitedReader`) but not time-bounded; a feed
that completes the handshake, returns 200, then trickles the body would hang
`FetchSnapshot`/`FetchDelta` forever. **Fix:** `Client.Timeout` + `DefaultTimeout` (5m) set
on the `http.Client` and as `ResponseHeaderTimeout`. Regression: `TestFetchTimeout` (a
stalled feed aborts at the deadline).

### SIMPLIFY — dead variable `end` in `splitHostPath`
`expr.go` — `end := len(u)` was never read (only `_ = end` to silence the compiler).
**Fix:** removed both.

### DEDUP — one hash-ordering comparator
The `func(a,b Hash) int { bytes.Compare(a[:],b[:]) }` closure appeared at three sites
(`NewSnapshot`, `sortedDedup`, `containsHash`) and the decoder's compare. **Fix:** a single
`compareHash` in `hash.go`; `NewSnapshot` now calls `sortedDedup`; `snapshot.go`/`delta.go`/
`store.go` dropped their `bytes` imports.

### DEDUP — `FetchSnapshot`/`FetchDelta` shared plumbing
The GET / body-cap / `ErrBodyTooLarge` / decode scaffolding was copied per type. **Fix:** a
generic `fetchDecode[T]` holds the (security-relevant) cap logic once; the two methods are
one-liners.

### DOC — "signed deltas" overstated
README / executive-summary / introduction said *signed* deltas, but deltas carry no
signature — they are **self-verifying** (base + target hash convergence) and integrity on
the wire is the TLS pin. **Fix:** wording → "self-verifying deltas". (The C-dimension
SECURITY framing of this was REFUTED — see below — it is a doc issue, not a vuln.)

### DOC — host-suffix off-by-one
`architecture.md` said "last-4…last-2" host suffixes; the code emits **last-5…last-2**
(exact + up to 4 suffixes, ≤5 total). **Fix:** doc + the `expr_test.go` comment.

### DOC — Delta wire-format row incomplete
`userguide.md` omitted the version byte and the two count fields from the Delta row.
**Fix:** row now lists `version · base · target · epoch · add-count · remove-count · adds · removes`.

## REFUTED — kept (with reason)

- **`Count > maxSnapCount` guard "redundant"** — a deliberate fail-fast that rejects a lying
  count before the SetHash read and stabilizes the `ErrTooLarge` identity. Kept.
- **`splitHostPath` "replaceable by net/url"** — it must NOT be: sieve keys on canonical
  bytes and the split is byte-exact/injected-canon by design. Kept.
- **`cuckoo.delete`/`removeFP` "dead in production"** — exercised by tests and reserved for
  incremental filter deltas; the delta path rebuilds the index today. Kept.
- **`Set.Hash()` "dead surface"** — the Phase-1 content-addressable prefix-index hash. Kept.
- **Decoder framing-preamble dedup** — the proposed shared `readPreamble` is unviable (the
  two headers diverge after the magic/version). Kept.
- **`datasetHash` "considered and NOT recommended"** — informational; no change proposed.
- **Delta "signed" SECURITY (`Apply` accepts a self-consistent forged delta) `*`** — the
  mechanism reproduces, but it is not a vuln: deltas were never signature-gated; integrity
  is the TLS-pinned transport + self-verifying convergence. Resolved as the DOC wording fix
  above, not by adding signing (out of scope for v0.1.0).
- **`Store.ApplyDelta` non-atomic load-modify-store** — true mechanically, but updates are
  single-writer by contract (one fetch loop); lock-free *reads* are the guarantee. Clarified
  in the `Store` doc comment rather than adding a CAS.
