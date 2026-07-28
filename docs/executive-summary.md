# Executive summary

**What it is.** sieve is the netstar URL-reputation *matcher* — the component a
partner runs to ask "is this URL on our list?" and get an exact yes/no offline,
with no call back to us per lookup.

**Why it exists.** Reputation lookup and URL *canonicalization* are different jobs
that were tangled together. Canonicalization ("one URL → one stable key") is the
shared crown-jewel contract; matching ("is this key listed?") is a distinct,
partner-facing datashipper. sieve is the second, carved out so each can be built,
tested, and shipped on its own — and so the matcher has zero dependencies and a
small, auditable trust surface.

**What it buys us.**
- **Exact, offline answers.** The dataset ships full hashes, so a prefix hit is
  confirmed locally — no ~1-in-4-billion false match, and no remote round-trip
  that would leak the queried URL.
- **Cheap distribution.** An immutable snapshot plus signed deltas; the live
  dataset swaps atomically, so lookups never block on an update.
- **Safe on the wire.** The fetch client caps the body (no OOM from a hostile
  feed) and pins the server key (no impersonation) — safeguards the file format
  leaves to the transport.
- **No silent drift.** The snapshot header stamps the canonicalization profile and
  IDNA mode; build and query must match, so a Unicode-host false-negative surfaces
  as a mismatch instead of a silent miss.

**Where it sits.** The lookup member of the **canonicalization** family, downstream
of the canonicalizer and a consumer of the reputation dataset the platform
produces.

**Status.** v0.1.0: the `Set`, cuckoo prefilter, snapshot/delta codecs, atomic
store, query + confirm tier, and fetch client are implemented and tested
(≈91% coverage, `-race` clean, decoders fuzzed). Incremental (non-rebuild) filter
deltas and a prefix-only snapshot mode are the next candidates.
