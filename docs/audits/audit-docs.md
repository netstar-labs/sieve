# Audit — doc / comment vs code drift (auditor D), 2026-09-29 pre-public pass

Scope: README.md, doc.go-equivalent package comments, every `docs/*.md`,
`example/README.md`. This pass's mandate included the **L4 private-repo-name
screen** — a hard blocker for going public — ahead of the usual doc-drift
sweep.

## PRIVATE-REPO-NAME SCREEN — NOT CLEAN, BLOCKER FOUND

Current tracked files (README, docs/*, code comments, go.mod, CLI help) are
clean — no private repo name appears anywhere in the working tree. **The
leak is in git history and the issue tracker**, both of which ship with the
repo the moment it goes public:

- **Issue #3** ("fetch.go: pin MinVersion to TLS 1.3 explicitly") — body
  names four currently-**private** sibling repos by path: `netstar-labs/scribe`,
  `signet/pkg/channel/pinning.go`, `scribe/relay/pinning.go`,
  `apiary/pkg/collector/tls.go`, `graphite/cmd/graphited/pinned_tls.go`.
  Closed, but stays visible in the Issues tab once public.
- **Commit `747a30b`** (on `main`, tagged `v0.1.1`) and **commit `1e7937b`**
  (the pre-squash commit, still live on `origin/fix/pin-tls13` — the branch
  was never deleted post-merge) — both commit **bodies** repeat the same
  four repo/path references verbatim, plus internal hostnames
  `feeds.nsgrid.co`/`bundles.nsgrid.co` as verification targets.

This is a **hard blocker per house policy** (L4-release-packaging §7): "a
leaked private name can't be un-published." It is **not fixed on this
branch** — the fix requires rewriting published git history (`main`'s
commit message, plus deleting/replacing `fix/pin-tls13`) and possibly
history on other clones/forks, which is a destructive, hard-to-reverse
operation outside what an audit-and-fix branch should do unilaterally.
Recorded here for the maintainer to action explicitly before flipping
visibility; see `docs/audits/audit-findings.md`'s summary for the
remediation options.

## Other drift, ranked by severity

**MISLEADING (fixed)** — `sieve.go`'s package doc comment (the most
externally-visible one — `go doc`/pkg.go.dev) still said "signed deltas",
the exact overstatement the 2026-07 audit fixed everywhere else (README,
executive-summary, introduction). Missed this one file. Fixed on this
branch (see the docs commit).

**OUTDATED (fixed)** — `docs/executive-summary.md`'s Status line was
stamped v0.1.0 (current is v0.1.2) and named "incremental filter deltas"/"a
prefix-only snapshot mode" as the next candidates — but the 2026-09-29
least-code pass removed the scaffolding for both as unreachable dead code.
Reworded so the roadmap line doesn't read as a continuation of work that
was just reversed. `docs/architecture.md`'s matching line updated the same
way. Fixed on this branch.

**OUTDATED (fixed)** — `docs/userguide.md`'s Delta wire-format row didn't
reflect this pass's own wire-format change (version bump, new
profile/expander/idna fields). Updated in the same commit as the fix.

## Confirmed clean (verified by execution, not just reading)

- 2026-09-29 dead-code cleanup completeness re-confirmed: zero hits for
  `removeFP`/`ConfirmNeeded`/`cuckoo.delete`/`Set.Hash()` outside the
  historical audit record.
- README data-flow diagram / CLI subcommands and flags: ran the actual
  binary, every subcommand's `-h` matches docs and code exactly.
- Every code example executed, not just read (library synopsis, CLI
  build→query, diff→apply, `example/embed`).
- go.mod / zero-dependency claim: confirmed, no non-stdlib imports anywhere.
- `Store` single-writer doc comment, `maxSnapCount` guard,
  `datasetHash`/`compareHash` dedup: all match the audit's REFUTED-kept
  items and the current code exactly.
