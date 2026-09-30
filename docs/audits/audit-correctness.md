# Audit — correctness + optimization (auditor C), 2026-09-29 pre-public pass

Scope: owned code — `sieve.go`, `hash.go`, `set.go`, `cuckoo.go`, `expr.go`,
`snapshot.go`, `delta.go`, `store.go`, `fetch.go`, `app/sieve/main.go`. Builds
on the 2026-07 torture-chamber audit and the 2026-09-29 least-code revisit
(`audit-findings.md`) — none of that ground is re-litigated here except where
explicitly noted.

## CONFIRMED and fixed

### 1. [SECURITY, sev:high] `Expand`'s cost scaled with input length, not the cap

`hostVariants`/`pathVariants` used `strings.Split`/`strings.SplitAfter` over
the WHOLE host/path before `Expand`'s ≤30-result cap ever applied — cost
proportional to input length regardless of the always-small output, on
`Matcher.Lookup`'s hot path with caller-supplied, potentially adversarial
input. Measured on the pre-fix code: a host or path built from 2M short
labels/segments cost ~27-35ms and a proportional multi-MB allocation per
`Lookup` call. Also found: a long dotted host with **no path at all** (no `/`
anywhere) is exploitable the same way — `splitHostPath` treats the whole
input as host, so `hostVariants`' `Split` alone pays the cost; a second
attack surface beyond the one first reported.

**Independently adversarially verified** before fixing: own timing
measurements (35.7ms/26.5ms on the two attack shapes, same order of
magnitude as the original report), confirmed no upstream length cap exists
anywhere in the codebase, confirmed the package's own docs frame it as a
per-request/latency-sensitive component (not a batch tool where this would
matter less), and confirmed a bounded-scan rewrite achieves byte-for-byte
identical output against every case in `expr_test.go`.

**Fix**: `hostVariants`/`pathVariants` rewritten as bounded right/left-
anchored scans (`strings.LastIndexByte`/`strings.IndexByte`, stopping after
finding enough labels/segments for the cap) instead of an eager full split.
This also removed the `seen`-maps in `Expand`/`pathVariants`, independently
found dead by auditor A (see `audit-simplify.md`) — duplicates in the host ×
path cross product are structurally impossible.

**Correction from a second finding, caught at final pre-merge verification**:
the first version of this rewrite was membership-preserving but NOT
order-preserving — walking right-to-left naturally finds a shorter host
suffix before a longer one, so it emitted suffixes least-specific-first,
the opposite of the original's and the doc comment's "most specific first".
Nothing in `expr_test.go` caught this (every assertion checks membership via
`slices.Contains`, never order). Not a security or `Verdict` regression
(every expression is still tried regardless of order), but
`Match.Expression` — the specific matched string a caller sees for
diagnostics — could silently change which candidate got reported first.
Fixed by collecting the found suffixes separately and reversing them before
returning (same bounded scan, negligible extra cost). Regression test added
(`TestHostVariantsOrder`, asserting the full ordered slice via
`slices.Equal`, not membership) and sabotage-verified.

**Residual, explicitly not claimed as fixed**: a single adversarial token
with NO delimiter at all still costs one O(n) scan to correctly conclude no
delimiter exists — inherent to a correct answer, not a rewriting artifact,
and measured to cost about the same on old and new code. The regression this
fix targets — many short labels/segments — drops from ~27-35ms to ~1-2ms.

Regression test: two "many short tokens" cases held to a 15ms bound
(calibrated against measured pre-fix timings with comfortable margin), two
"single giant token" cases checked only for correctness within a generous
1s bound. Sabotage-verified: reverting to the pre-fix implementation makes
exactly the two tight-bound subtests fail, not the other two.

### 2. [SECURITY, sev:med] CLI local-file reads had no size cap

The fetch path (`fetchDecode`) already bounds a fetched body at
`DefaultMaxBody` via `io.LimitedReader`, but the CLI's own local-file reads
didn't: `readSnapshot` (used by `query`, `diff`, `apply`) and `apply`'s delta
read called `os.Open` + `Decode`/`DecodeDelta` directly, with no cap. A
well-formed (non-lying) snapshot file of ~2^30 entries × 32B (~34 GiB) — the
only remaining ceiling, `maxSnapCount` — or a `diff`/`apply` combining two
such files, would make the CLI attempt to allocate tens of GB with zero
governance. Not a decompression bomb (no compression; cost is proportional
to file size) but unmitigated outside the one path already hardened — and
"a third party runs the CLI against an arbitrary snapshot file" is exactly
the documented threat model once this ships publicly.

A crafted lying count was already fine (rejected cheaply via `ErrTruncated`
on the first short read); this closes the case of a file that's genuinely
that large.

**Fix**: `readSnapshot`/`readDelta` wrap the file in an `io.LimitedReader` at
an injectable `maxBody+1` (both CLI callers pass `sieve.DefaultMaxBody`),
returning `sieve.ErrBodyTooLarge` when exceeded — mirroring `fetchDecode`'s
exact mechanism. Regression tests build a real file, then call the read
functions with a cap one byte under and one byte over the file's actual
size, confirming the boundary in both directions. Sabotage-verified.

### 3. [BUG, sev:high] `Delta.Apply` silently inherited the wrong canonicalization stamp

`Delta.Apply` always copied Profile/Expander/IDNA from **base**
unconditionally; neither `Apply` nor the CLI's `diff()` ever checked base's
stamps against target's. `SetHash`/`datasetHash` is purely a function of hash
bytes, so the existing Base/Target convergence check cannot detect a
canonicalization-profile change — a delta computed by diffing a snapshot
built under profile "url/1" against one built under "url/2" applied cleanly
(converges, no error) and produced a snapshot whose header claimed "url/1"
while its hashes were actually computed under "url/2". The package's own doc
already names this exact class of mismatch as security-relevant.

**Escalated by the adversarial skeptic**: this is worse than a CLI-diff-
misuse edge case. The documented production path is fetch → `ApplyDelta`,
and since `Delta`'s wire format carried no target stamps at all, a check
confined to the CLI's `diff()` could never close the gap for a fetched
delta — nothing existed for `Apply` to check against, at any layer.

**Fix**: `Delta` gains its own `Profile`/`Expander`/`IDNA` fields (the
target's stamps); `deltaVersion` bumps 1→2 (wire-incompatible, deliberately
— see the commit for why this is the right time). `Apply` refuses with the
new `ErrStampMismatch` when these don't match base's current stamps,
checked right after the existing Base-hash check. `diff()` populates the
new fields from the target snapshot. Regression test
(`TestDeltaStampMismatch`) reproduces the real cross-profile scenario;
`TestDeltaRoundTrip` extended for the new wire fields. Four existing tests
needed matching stamps added to their hand-built `Delta` literals — each
failure confirmed (via sabotage-verify) to be the new check firing
correctly, not a bug the fix exposed.

## MINOR, documented not code-changed

### 4. `Client.HTTP`'s doc comment didn't say it disables pinning

If `Client.HTTP` is set, `PinSHA256` is silently ignored entirely (the early
return in `httpClient()` skips the pinning logic before it ever runs) — the
field's doc comment ("nil => a client built from PinSHA256") didn't say the
other half. A real footgun for a security-sensitive field on a public
library, cheap to fix with a doc-comment sentence rather than a behavior
change (this is the standard, minimal "bring your own transport" escape
hatch, not a bug to remove).

### 5. `writeFile` discarded `f.Close()`'s error on the encode-failure path

On success it correctly returns `Close`'s error; on `encode` failure it
called `Close` but only propagated `encode`'s error. Cosmetic (the command
already fails either way) — fixed with `errors.Join` rather than silently
dropped, at negligible cost.

## Clean checks performed (traced/run against the real package)

- **Wire-codec integer bounds** (both the original A1 pass and this one):
  every length/count field is checked against a cap before sizing any
  allocation; pre-allocation capacity is separately capped so a lying huge
  count cannot pre-allocate. No panics possible on crafted input by
  construction.
- **`fetchDecode`'s cap-boundary math**: traced the exact boundary
  (`maxBody` bytes accepted, `maxBody+1` rejected); a decode error from
  starvation is correctly overridden by the size-cap error.
- **Cuckoo filter saturation**: built a small table, inserted until 100%
  load — no infinite loop, no corruption, `contains()` correctly falls
  through to the authoritative confirm tier post-saturation, preserving the
  no-false-negative guarantee.
- **`atomic.Pointer` swap concurrency**: `-race` stress test, one writer
  against 8 concurrent readers — no race, no torn-index read.
- **Resource leaks**: all 5 CLI subcommands close every opened file/reader
  on every return path.
