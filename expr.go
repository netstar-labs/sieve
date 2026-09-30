package sieve

import (
	"net"
	"slices"
	"strings"
)

// maxExpressions caps the fan-out at 30 (≤5 host suffixes × ≤6 path prefixes) —
// the standard URL-expression expansion. Expansion is a lookup-side concern: one
// canonical key becomes up to thirty candidate expressions to test, so listing
// "example.com/bad" also matches "example.com/bad/sub" and "sub.example.com/bad".
const maxExpressions = 30

// Expand turns one canonical URL into the ≤30 host-suffix × path-prefix
// expressions to hash and test, most specific first. Input is a canonical key
// (any leading scheme is stripped); each output is a host+path string. An IP
// host is not suffix-expanded.
//
// The cross product never needs deduping: host variants are pairwise distinct
// (each has a different label count, since hostVariants only ever emits the
// exact host plus strictly-shorter label-count suffixes), path variants are
// pairwise distinct (the query variant is strictly longer than and contains a
// byte, '?', absent from every prefix of the path; directory prefixes strictly
// increase in length and the exact path is never re-added as one), and since a
// host never contains '/' while a path always starts with '/', any h+p
// concatenation decomposes back to (h, p) uniquely at the first '/' — so
// distinct pairs can never collide. Verified both structurally and empirically
// (2M+ randomized + an exhaustive small-alphabet sweep, 0 duplicates) during
// an A1 audit pass; the seen-map this function used to carry was dead code.
func Expand(canonical string) []string {
	host, path := splitHostPath(canonical)
	if host == "" {
		return nil
	}
	hosts := hostVariants(host)
	paths := pathVariants(path)
	out := make([]string, 0, min(len(hosts)*len(paths), maxExpressions))
	for _, h := range hosts {
		for _, p := range paths {
			out = append(out, h+p)
			if len(out) >= maxExpressions {
				return out
			}
		}
	}
	return out
}

// splitHostPath strips a scheme and splits into host and path (path always begins
// with "/"). The host ends at the first "/" or "?".
func splitHostPath(u string) (host, path string) {
	if i := strings.Index(u, "://"); i >= 0 {
		u = u[i+3:]
	}
	slash := strings.IndexByte(u, '/')
	q := strings.IndexByte(u, '?')
	switch {
	case slash < 0 && q < 0:
		return u, "/"
	case slash < 0 || (q >= 0 && q < slash):
		// query before any path separator: host ends at '?', path is "/?..."
		return u[:q], "/" + u[q:]
	default:
		return u[:slash], u[slash:]
	}
}

// hostVariants returns the exact host plus up to four suffixes (last-5 … last-2
// labels), ≤5 total. An IP host returns just itself.
//
// Bounded scan, not strings.Split: a Split materializes one slice entry per
// label in the WHOLE host before any cap can apply, so a crafted host with an
// unbounded number of labels costs CPU/memory proportional to its full length
// on every call — a real CPU/memory-amplification DoS vector for a function
// on Lookup's hot path, called on caller-supplied, potentially adversarial
// input (found + adversarially verified in an A1 audit pass). Walking from the
// right and stopping after at most 4 dots reproduces the identical output
// (verified against every case in expr_test.go) while costing only the length
// of the last ~5 labels, not the whole host.
func hostVariants(host string) []string {
	if isIP(host) {
		return []string{host}
	}
	end := len(host)
	// Consume the rightmost dot (the last-1 boundary) without storing it — the
	// suffix expansion never goes below 2 labels.
	if i := strings.LastIndexByte(host[:end], '.'); i >= 0 {
		end = i
	} else {
		return []string{host} // single label, no dot at all: no shorter suffix exists
	}
	// Walking right-to-left finds shorter suffixes first (last-2, then last-3,
	// ...) — the opposite of "most specific first". Collect them separately and
	// reverse before appending, so the returned order matches the original
	// longest-suffix-first contract exactly (found and fixed during final
	// pre-merge verification: the first version of this bounded scan changed
	// the emission order, which nothing in expr_test.go's membership-only
	// assertions caught — Lookup's Verdict is order-independent, so this
	// wasn't a correctness bug, but Match.Expression — the specific matched
	// string a caller sees for diagnostics/logging — could silently change
	// which candidate gets reported first).
	var suffixes []string
	for len(suffixes) < 4 {
		i := strings.LastIndexByte(host[:end], '.')
		if i < 0 {
			break // fewer labels than the cap; the rest IS the whole host, already added
		}
		suffixes = append(suffixes, host[i+1:])
		end = i
	}
	slices.Reverse(suffixes)
	return append([]string{host}, suffixes...)
}

// pathVariants returns the exact path (with and, if it has one, without query)
// plus up to four leading directory prefixes ("/", "/a/", "/a/b/", "/a/b/c/"),
// ≤6 total.
//
// Bounded scan, not strings.SplitAfter: SplitAfter materializes one slice
// entry per "/"-delimited segment in the WHOLE path before the loop's early
// break on reaching 4 directories ever runs — the same unbounded-cost shape as
// hostVariants above, on the same hot path. Scanning forward and stopping
// after finding the 4th "/" reproduces the identical output (verified against
// every case in expr_test.go) while never touching path bytes beyond the 4th
// directory boundary.
func pathVariants(path string) []string {
	base, query := path, ""
	if i := strings.IndexByte(path, '?'); i >= 0 {
		base, query = path[:i], path[i:]
	}
	out := make([]string, 0, 6)
	if query != "" {
		out = append(out, base+query)
	}
	out = append(out, base)
	pos, dirs := 0, 0
	for dirs < 4 {
		i := strings.IndexByte(base[pos:], '/')
		if i < 0 {
			break
		}
		pos += i + 1
		if pos == len(base) {
			break // this boundary is the whole path — already added above
		}
		out = append(out, base[:pos])
		dirs++
	}
	return out
}

func isIP(host string) bool {
	h := host
	if strings.HasPrefix(h, "[") && strings.HasSuffix(h, "]") {
		h = h[1 : len(h)-1]
	}
	return net.ParseIP(h) != nil
}
