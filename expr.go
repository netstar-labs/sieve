package sieve

import (
	"net"
	"strings"
)

// maxExpressions caps the fan-out at 30 (≤5 host suffixes × ≤6 path prefixes) —
// the standard URL-expression expansion. Expansion is a lookup-side concern: one
// canonical key becomes up to thirty candidate expressions to test, so listing
// "example.com/bad" also matches "example.com/bad/sub" and "sub.example.com/bad".
const maxExpressions = 30

// Expand turns one canonical URL into the ≤30 host-suffix × path-prefix
// expressions to hash and test, most specific first, deduped. Input is a
// canonical key (any leading scheme is stripped); each output is a host+path
// string. An IP host is not suffix-expanded.
func Expand(canonical string) []string {
	host, path := splitHostPath(canonical)
	if host == "" {
		return nil
	}
	hosts := hostVariants(host)
	paths := pathVariants(path)
	out := make([]string, 0, len(hosts)*len(paths))
	seen := make(map[string]struct{}, len(hosts)*len(paths))
	for _, h := range hosts {
		for _, p := range paths {
			e := h + p
			if _, dup := seen[e]; dup {
				continue
			}
			seen[e] = struct{}{}
			out = append(out, e)
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
	end := len(u)
	slash := strings.IndexByte(u, '/')
	q := strings.IndexByte(u, '?')
	switch {
	case slash < 0 && q < 0:
		return u, "/"
	case slash < 0 || (q >= 0 && q < slash):
		// query before any path separator: host ends at '?', path is "/?..."
		return u[:q], "/" + u[q:]
	default:
		_ = end
		return u[:slash], u[slash:]
	}
}

// hostVariants returns the exact host plus up to four suffixes (last-5 … last-2
// labels), ≤5 total. An IP host returns just itself.
func hostVariants(host string) []string {
	if isIP(host) {
		return []string{host}
	}
	labels := strings.Split(host, ".")
	n := len(labels)
	out := []string{host}
	start := min(n, 5)
	for k := start; k >= 2 && len(out) < 5; k-- {
		if k == n {
			continue // the exact host, already present
		}
		out = append(out, strings.Join(labels[n-k:], "."))
	}
	return out
}

// pathVariants returns the exact path (with and, if it has one, without query)
// plus up to four leading directory prefixes ("/", "/a/", "/a/b/", "/a/b/c/"),
// deduped, ≤6 total.
func pathVariants(path string) []string {
	base, query := path, ""
	if i := strings.IndexByte(path, '?'); i >= 0 {
		base, query = path[:i], path[i:]
	}
	out := make([]string, 0, 6)
	seen := make(map[string]struct{}, 6)
	add := func(p string) bool {
		if _, dup := seen[p]; dup {
			return len(out) < 6
		}
		seen[p] = struct{}{}
		out = append(out, p)
		return len(out) < 6
	}
	if query != "" {
		if !add(base + query) {
			return out
		}
	}
	if !add(base) {
		return out
	}
	// up to four directory prefixes, shortest first
	prefix := ""
	dirs := 0
	for _, c := range strings.SplitAfter(base, "/") {
		prefix += c
		if strings.HasSuffix(prefix, "/") && prefix != base {
			if !add(prefix) {
				return out
			}
			if dirs++; dirs >= 4 {
				break
			}
		}
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
