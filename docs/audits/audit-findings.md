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

## Revisited, 2026-09-29 — least-code pass

A later least-code audit reopened three of the items kept above, applying a narrower test
(rung 1 of the ladder: does a caller exist *today*, not the one a future feature would need)
than this audit did. All three of this audit's own kept-reasons named a future feature with
no design doc, no issue, and — confirmed by re-grepping the repo — no caller: `cuckoo.delete`/
`removeFP` (incremental filter deltas), `ConfirmNeeded` (a prefix-only snapshot mode; also
confirmed unreachable from any real construction path, since the confirm tier and the Set/
filter are always co-derived from the same hash slice), and `Set.Hash()` (a Phase-1
content-addressable prefix-index hash). All three removed, along with the tests written to
exercise them and every doc line that referenced them (including two doc-comment claims,
`cuckoo.go` and `delta.go`, that deletion is why the prefilter is a cuckoo rather than a
Bloom filter — inaccurate independent of this change, since delta application has always
rebuilt the filter rather than mutating it incrementally). ~40 lines removed, zero behavior
change to any currently reachable code path.

## Pre-public pass, 2026-09-29 — full A1 re-audit + L4 release prep

Requested ahead of going public. Same four-dimension torture-chamber method plus
least-code, run fresh; full per-dimension detail in `audit-simplify.md` /
`audit-dedup.md` / `audit-correctness.md` / `audit-docs.md` (new files, this pass).
**3 CONFIRMED (2 sev:high security/correctness, 1 sev:med security) · 2 MINOR
documented · several dedup/simplify/doc fixes · 1 BLOCKER found, not fixed.**

### CONFIRMED and fixed (all independently adversarially verified before applying)

- **[security, sev:high] `Expand`'s cost scaled with input length, not the
  ≤30 cap** — `hostVariants`/`pathVariants` eagerly split the whole host/path
  before the cap ever applied; a crafted host/path with many short labels/
  segments cost ~27-35ms and a proportional multi-MB allocation per `Lookup`
  call (also found: a long dotted host with no path at all is exploitable
  the same way). Fixed with a bounded-scan rewrite, byte-for-byte identical
  output verified against every existing test.
- **[security, sev:med] CLI local-file reads (`readSnapshot`/`apply`'s delta
  read) had no size cap**, unlike the fetch path. A well-formed multi-GB
  file could make the CLI attempt an unbounded allocation. Fixed by
  wrapping both in the same `io.LimitedReader` mechanism `fetchDecode`
  already uses.
- **[bug, sev:high] `Delta.Apply` silently inherited the base snapshot's
  canonicalization stamp instead of validating against the target's** —
  `SetHash` convergence can't detect a profile change, so a delta diffed
  across a canonicalization-profile bump applied cleanly with a header that
  lied about which scheme produced its hashes. Escalated by the adversarial
  skeptic: this also affected the primary fetch→`ApplyDelta` production
  path, not just CLI misuse, because `Delta`'s wire format carried no target
  stamps at all. Fixed with a wire-format version bump (`deltaVersion`
  1→2, wire-incompatible): `Delta` now carries its own Profile/Expander/IDNA,
  and `Apply` refuses with a new `ErrStampMismatch` on mismatch.

### MINOR — documented, not code-changed

- `Client.HTTP`'s doc comment didn't say a caller-supplied client silently
  disables `PinSHA256`. Documented; not a bug to fix (standard "bring your
  own transport" escape hatch).
- `writeFile` discarded `f.Close()`'s error on the encode-failure path.
  Fixed trivially with `errors.Join`.

### Applied (dedup / simplify / doc, no behavior change)

- Dedup: a shared `readExact`/`readUint32`/`readUint64` wire-field
  primitive (the prior pass's dedup reached `delta.go` but not the matching
  field in `snapshot.go`); `diff()`'s adds/removes via sorted merge instead
  of two hash maps (verified equivalent via 200K trials).
- Simplify / least-code: `Expand`'s dead dedup maps removed (duplicates
  proven structurally impossible, 2M+ trial brute force); `Store`/
  `NewStore` unexported (zero real external callers) and `Header.Version`
  dropped (write-only, zero real read) — both API-surface reductions
  applied now specifically because this is the last point before either
  becomes a breaking change for an external consumer.
- Docs: `sieve.go`'s package doc comment still said "signed deltas" (the
  2026-07 audit's own fix missed this one file); `docs/executive-summary.md`
  and `docs/architecture.md`'s version/status lines were stale and named
  removed scaffolding as "next candidates"; `docs/userguide.md`'s Delta
  wire-format row updated for the new fields.

### BLOCKER — found, NOT fixed (requires explicit sign-off)

**Private-repo-name leak in git history and the issue tracker.** Issue #3's
body and two commits (`747a30b` on `main`, tagged `v0.1.1`; `1e7937b`, still
live on `origin/fix/pin-tls13`, never deleted post-merge) name four
currently-private sibling repos (`scribe`, `signet`, `apiary`, `graphite`)
by path, plus internal hostnames. Per house policy (L4-release-packaging
§7) this is a hard blocker for the visibility flip — "a leaked private name
can't be un-published." **Not remediated on this branch**: fixing it means
(a) editing issue #3's body via the GitHub API (safe, no history rewrite),
and (b) rewriting the two commits' messages and deleting/replacing
`fix/pin-tls13` (a destructive, hard-to-reverse operation on published
history), which needs the repo owner's explicit go-ahead before it's done,
not a unilateral action from an audit pass. See `audit-docs.md` for the
full trace.

### Re-validation gate

`go build`/`vet`/`staticcheck`/`gofmt -l`/`deadcode` clean; `go test -race
./...` green across every commit; fuzz smoke run (`FuzzSnapshotDecode`,
`FuzzDecodeDelta`) clean; `govulncheck ./...` clean. Every fix carries a
regression test, sabotage-verified (revert → confirm an attributable
failure → restore → confirm green).
