# sieve — catch only what you came for

*Millions of URLs fall straight through the mesh; the handful you're hunting stay behind.*

A sieve sorts by passing the ordinary through and catching only what you are
looking for. This one is handed a URL and asked a single question — *is this one
listed?* — and it answers by letting the vast majority fall straight through and
catching the few that match a known-bad expression.

**What it actually is:** a Go library and CLI that tests a URL against a netstar
reputation dataset. A query URL is canonicalized to one uniform key, expanded into
the ≤30 host-suffix × path-prefix expressions a listing might have been published
at, and each is SHA-256 hashed. A compact cuckoo filter and a sorted 32-bit prefix
set discard the clean cases in a cache line or two; the handful that survive are
confirmed against a sorted table of full hashes, so a hit is *exact*. The dataset
is an immutable snapshot evolved by self-verifying deltas, held behind an atomic pointer
so millions of lookups read it without a lock while a new one swaps in underneath.

**The thing nobody else gives you here:** exactness with no phone-home. Because the
dataset ships the full hashes, sieve confirms a prefix locally — there is no remote
round-trip to resolve a collision, and no leak of which URL you asked about. It is
the lookup half of a deliberately split contract: *canonicalization* ("one URL →
one key") is a separate concern, injected so that the party building the dataset
and the party querying it agree on it byte-for-byte.

**The control you keep:** you own the dataset and its granularity (list a host, a
directory, or an exact URL — the publisher decides), you pin the canonicalization
in the snapshot header so a mismatch is detectable rather than silent, and you pin
the server key and cap the body when you fetch, so a hostile feed can neither
impersonate the source nor exhaust your memory.

*Read next:* [architecture](architecture.md) · [user guide](userguide.md)
