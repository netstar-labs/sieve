# Audit — simpler pathways (auditor A) + least-code, 2026-09-29 pre-public pass

Scope: owned code (same as `audit-correctness.md`). Builds on the 2026-07
audit and the 2026-09-29 least-code revisit (`audit-findings.md`) — neither
re-litigated except where a genuinely new angle is noted.

## Fixed in this pass

**`Expand`'s dead dedup maps** — `Expand`'s outer `seen` map and
`pathVariants`' internal `seen`/`add` closure existed to prevent duplicate
expression strings, but duplicates are structurally impossible: host
variants are pairwise distinct (each has a different label count), path
variants are pairwise distinct (the query variant is strictly longer than
and contains a byte absent from every path prefix; directory prefixes
strictly increase in length), and since a host never contains `/` while a
path always starts with one, any `h+p` concatenation decomposes back to
`(h, p)` uniquely — so distinct pairs can never collide. Verified both
structurally and empirically (2M+ randomized trials + an exhaustive
small-alphabet sweep, 0 duplicates) before removing. Folded into the same
rewrite as the security fix in `audit-correctness.md` finding 1, since both
touch the same functions.

**API-surface reductions** (see `audit-dedup.md`'s sibling doc and the
commit `refactor: shrink the public API before it ships`):
- `Store`/`NewStore` unexported — zero real external callers, and the only
  read path (`current()`) was already unexported, so a directly-constructed
  `sieve.NewStore()` was write-only from outside the package. Applied now
  specifically because unexporting is a breaking change once external
  consumers exist — this is the cheapest point to do it.
- `Header.Version` dropped — written on every construction path, read by
  nothing (`Encode` writes the `snapVersion` constant directly, not the
  field); `Decode` already rejects any version but the pinned one before
  ever storing it, so the field could only ever hold that one value.

## Considered and NOT applied

**`MixedScript`-style delegation is not applicable here** (that was a
unmask finding); no analog pattern found in this repo's owned files.

**`Client.HTTP`/`PinSHA256` interaction** — considered as a possible API
change (e.g., refuse to combine a caller-supplied `HTTP` with a set
`PinSHA256`, since the latter is silently ignored), but this is the
standard, minimal "bring your own transport" escape hatch every Go HTTP
client wrapper needs, not excess surface — documented instead (see
`audit-correctness.md` finding 4), not removed or restricted.

## What was checked and already minimal (no finding)

- `internal/gen`-equivalent machinery: N/A, this repo has no code generator.
- `splitHostPath` vs. `net/url`: re-confirmed still correctly refused (byte-
  exact/injected-canon by design) — no new angle found.
- The cuckoo filter and the custom binary wire codec: the actual product
  this repo exists to provide, not unnecessary complexity vs. a
  hypothetical stdlib/library replacement.
- All 5 CLI subcommands: every flag is read and wired through; no dead
  flags, no unused config knobs.
