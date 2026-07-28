package sieve

import (
	"slices"
	"strings"
	"testing"
)

func mustHave(t *testing.T, got []string, want ...string) {
	t.Helper()
	for _, w := range want {
		if !slices.Contains(got, w) {
			t.Errorf("missing %q in %v", w, got)
		}
	}
}

func TestExpandPathPrefixes(t *testing.T) {
	got := Expand("http://example.com/a/b/c")
	mustHave(t, got, "example.com/a/b/c", "example.com/a/b/", "example.com/a/", "example.com/")
}

func TestExpandHostSuffixes(t *testing.T) {
	got := Expand("http://a.b.example.com/x")
	mustHave(t, got, "a.b.example.com/x", "b.example.com/x", "example.com/x", "example.com/")
}

func TestExpandQuery(t *testing.T) {
	got := Expand("http://example.com/p?q=1")
	mustHave(t, got, "example.com/p?q=1", "example.com/p", "example.com/")
}

func TestExpandIPNotSuffixed(t *testing.T) {
	for _, e := range Expand("http://1.2.3.4/x/y") {
		if !strings.HasPrefix(e, "1.2.3.4/") {
			t.Errorf("IP host was suffix-expanded: %q", e)
		}
	}
}

func TestExpandCap(t *testing.T) {
	got := Expand("http://a.b.c.d.e.f.g/1/2/3/4/5/6?q=1")
	if len(got) > maxExpressions {
		t.Errorf("expansion count %d exceeds cap %d", len(got), maxExpressions)
	}
	// no duplicates
	seen := map[string]bool{}
	for _, e := range got {
		if seen[e] {
			t.Errorf("duplicate expression %q", e)
		}
		seen[e] = true
	}
}

func TestExpandBareHost(t *testing.T) {
	mustHave(t, Expand("example.com"), "example.com/")
}

func TestExpandHostCapFive(t *testing.T) {
	// a deep host yields at most 5 host variants (exact + last-5..last-2 suffixes).
	got := Expand("a.b.c.d.e.f.example.com/")
	hosts := map[string]bool{}
	for _, e := range got {
		hosts[strings.SplitN(e, "/", 2)[0]] = true
	}
	if len(hosts) > 5 {
		t.Errorf("host variants = %d, want <= 5: %v", len(hosts), hosts)
	}
}
