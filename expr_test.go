package sieve

import (
	"slices"
	"strings"
	"testing"
	"time"
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

// hostVariants/pathVariants used to strings.Split/SplitAfter the WHOLE input
// before the cap ever applied — cost proportional to input length regardless
// of the always-<=30 output, on Lookup's hot path with caller-supplied,
// potentially adversarial input (found in an A1 audit pass). Measured on the
// pre-fix code: 2M short host labels cost ~27ms, 2M short path segments
// ~35ms (vs. ~1-2ms after the bounded-scan fix) — a many-short-tokens input
// is where Split's per-label slice allocation actually bites; a single giant
// token with no delimiter costs about the same either way (one O(n) scan to
// prove no delimiter exists is inherent to a correct answer, not fixable by
// rewriting the split — the fix targets the many-tokens case, so that's the
// one this test holds to a tight bound; the single-token cases only need to
// complete and answer correctly, not race the clock).
func TestExpandAdversarialLengthIsBounded(t *testing.T) {
	cases := []struct {
		name    string
		in      string
		timeout time.Duration
	}{
		{"2M short host labels, no path", strings.Repeat("a.", 2_000_000) + "example.com", 15 * time.Millisecond},
		{"2M short path segments", "example.com" + strings.Repeat("/a", 2_000_000), 15 * time.Millisecond},
		{"one 4MB host label, no dots", strings.Repeat("a", 4_000_000), time.Second},
		{"one 4MB path segment, no /", "example.com/" + strings.Repeat("a", 4_000_000), time.Second},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			done := make(chan []string, 1)
			start := time.Now()
			go func() { done <- Expand(c.in) }()
			select {
			case got := <-done:
				if elapsed := time.Since(start); elapsed > c.timeout {
					t.Errorf("Expand took %s, want under %s", elapsed, c.timeout)
				}
				if len(got) == 0 {
					t.Error("Expand returned no expressions for a non-empty host")
				}
				if len(got) > maxExpressions {
					t.Errorf("Expand returned %d expressions, want <= %d", len(got), maxExpressions)
				}
			case <-time.After(c.timeout):
				t.Fatalf("Expand did not return within %s", c.timeout)
			}
		})
	}
}

// hostVariants' bounded-scan rewrite (above) originally emitted suffixes in
// the WRONG order (shortest-first, since walking right-to-left naturally
// finds a shorter suffix before a longer one) -- a real, silent behavior
// change from the documented "most specific first" contract that slipped
// past every other test here, since mustHave/slices.Contains only check
// membership, never order. Verdict/Set-membership is order-independent so
// this wasn't a security bug, but Match.Expression (the specific matched
// string a caller sees for diagnostics) could silently change which
// candidate got reported. Found in an independent final-verification pass;
// fixed by reversing the collected suffixes before returning. This test
// asserts the full ordered slice, not just membership, so a reintroduced
// order bug fails here specifically.
func TestHostVariantsOrder(t *testing.T) {
	got := hostVariants("a.b.c.example.com")
	want := []string{"a.b.c.example.com", "b.c.example.com", "c.example.com", "example.com"}
	if !slices.Equal(got, want) {
		t.Errorf("hostVariants(a.b.c.example.com) = %v, want %v (most-specific-first)", got, want)
	}
}
