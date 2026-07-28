# sieve

A standalone, partner-facing **URL-reputation matcher**: *is this URL in our
dataset?* — answered offline, exactly, and lock-free against a netstar dataset
shipped as an immutable snapshot plus signed deltas.

```
  URL ─▶ canonicalize ─▶ Expand (≤30 host×path) ─▶ SHA-256
                                                      │
                                        ┌─ cuckoo prefilter (fast "no")
                                        ├─ uint32 prefix Set (binary search)
                                        └─ full-hash confirm tier ─▶ Verdict {Listed | Clean}
        dataset: Snapshot ──delta──▶ Snapshot   (atomic swap; lock-free reads)
```

Canonicalization is a separate concern ("one URL → one key"), injected here as a
seam so build and query agree on it; sieve itself has **zero external
dependencies**. A match is exact — the dataset ships full hashes, so there is no
~1-in-4-billion prefix collision and no remote round-trip.

## Docs

- **Start here** — [introduction](docs/introduction.md) · [executive summary](docs/executive-summary.md)
- **Deep dive** — [architecture](docs/architecture.md)
- **Operations** — [user guide](docs/userguide.md)
- **Examples** — [example/](example/README.md)

## Layout

| File | Purpose |
|---|---|
| [sieve.go](sieve.go) | Package doc, the `Canon` seam, `Verdict`/`Match`, and the `Matcher` facade (`New`/`Install`/`ApplyDelta`/`Lookup`). |
| [hash.go](hash.go) | `Hash`, `HashURL`, `Prefix`, and the dataset identity hash. |
| [set.go](set.go) | `Set` — the sorted/deduped `[]uint32` prefix prefilter (binary search + `Hash`). |
| [cuckoo.go](cuckoo.go) | The cuckoo filter — no false negatives, deletable, saturate-safe. |
| [expr.go](expr.go) | `Expand` — host-suffix × path-prefix expansion (≤30). |
| [snapshot.go](snapshot.go) | `Snapshot` + the attacker-facing wire codec. |
| [delta.go](delta.go) | `Delta` + codec + self-verifying `Apply`. |
| [store.go](store.go) | `Store` — the immutable index behind an `atomic.Pointer` swap. |
| [fetch.go](fetch.go) | `Client` — HTTPS fetch with a body size cap + TLS public-key pinning. |

`app/sieve/` is the CLI (`build`/`query`/`diff`/`apply`/`fetch`); `build/sieve`
cross-compiles it.
