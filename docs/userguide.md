# User guide

## Library

```go
// Wire the netstar canonicalizer into the seam (nil ⇒ input treated as canonical).
m := sieve.New(canon)

snap, err := sieve.Decode(r)        // r is a snapshot stream
if err != nil { /* … */ }
m.Install(snap)

v := m.Lookup("http://example.com/bad")
if v.IsListed() {
    log.Printf("listed: matched %q under profile %s / idna %s", v.Expression, v.Profile, v.IDNA)
}

// Evolve without a full reload:
d, _ := sieve.DecodeDelta(deltaStream)
if err := m.ApplyDelta(d); err != nil { /* wrong base / non-convergent */ }
```

`Lookup` returns a `Match`: `Verdict` (`Clean` / `Listed`), the
matching `Prefix` and `Expression`, and the dataset stamps (`Profile`, `Expander`,
`IDNA`). Reads are lock-free and safe under concurrency; `Install`/`ApplyDelta`
swap the dataset atomically.

### Fetching over the wire

```go
c := &sieve.Client{
    BaseURL:   "https://example.com",
    MaxBody:   256 << 20,       // cap the body (0 ⇒ 1 GiB default)
    PinSHA256: spkiPin,          // SHA-256 of the server leaf SPKI
}
snap, err := c.FetchSnapshot("/reputation/latest.snap")
```

## CLI

```
sieve build -o SNAP [-profile P -expander E -idna I -epoch N] LISTFILE
sieve query -snap SNAP URL [URL...]
sieve diff  -base A -target B -o DELTA
sieve apply -snap BASE -delta DELTA -o OUT
sieve fetch -url URL [-pin SHA256HEX -max BYTES] -o SNAP
```

- **build** — hash one canonical expression per line of `LISTFILE` (`#` comments
  and blank lines skipped) into a snapshot. The stamps you pass must match the
  canonicalization the entries were produced under.
- **query** — decode `SNAP` and print a verdict per URL (input assumed canonical;
  production wires the canonicalizer).
- **diff** — compute the delta from `base` to `target`.
- **apply** — apply a delta to a base snapshot (refuses a wrong base or a
  non-convergent result).
- **fetch** — download a snapshot with a body cap and optional SPKI pin.

```sh
printf 'evil.com/\nexample.com/bad\n' > list.txt
sieve build -o rep.snap -profile url/1 -expander expr/1 -idna idna:15.0.0 list.txt
sieve query -snap rep.snap http://example.com/bad http://good.com/
# listed   http://example.com/bad  (matched "example.com/bad")
# clean    http://good.com/
```

## Wire formats

Both codecs are attacker-facing and validate on decode (bounded allocation,
strictly-increasing order, checksum / self-verifying convergence). See
[architecture.md](architecture.md#distribution).

| | Magic | Body |
|---|---|---|
| Snapshot | `SIEV` | header (version · profile · expander · idna · epoch · count · dataset-hash) + sorted full hashes |
| Delta | `SIVD` | version · base · target · epoch · add-count · remove-count · adds · removes (each sorted) |

## Operational notes

- **Pin canonicalization.** Build and query must share the same profile/expander/
  IDNA stamps; a mismatch means Unicode-host lookups silently miss.
- **Fetch safely.** Always set a `MaxBody` and a `PinSHA256` for a partner-facing
  deployment — the format leaves both to you.
- **Updates are cheap.** Poll for a delta and `ApplyDelta`; the swap is atomic and
  readers never block.
