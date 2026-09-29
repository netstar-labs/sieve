package sieve

import "testing"

func TestMatcherEndToEnd(t *testing.T) {
	m := New(lc)
	m.Install(listing("evil.com/", "example.com/bad"))

	// host-suffix coverage: listing "evil.com/" catches any path on any subdomain
	if v := m.Lookup("http://EVIL.com/whatever/page"); v.Verdict != Listed {
		t.Errorf("host-suffix listing missed: %+v", v)
	}
	// exact path listing
	if v := m.Lookup("http://example.com/bad"); !v.IsListed() {
		t.Errorf("exact listing missed: %+v", v)
	}
	// a sibling path under the same host is NOT listed (exact-coverage policy)
	if v := m.Lookup("http://example.com/other"); v.Verdict != Clean {
		t.Errorf("path false positive: %+v", v)
	}
	// an unrelated host is clean
	if v := m.Lookup("http://good.com/"); v.Verdict != Clean {
		t.Errorf("host false positive: %+v", v)
	}
	// the result carries the dataset stamps
	v := m.Lookup("http://example.com/bad")
	if v.Profile != "url/1" || v.Expander != "expr/1" || v.IDNA != "idna:15.0.0" {
		t.Errorf("stamps missing: %+v", v)
	}
	if v.Expression == "" {
		t.Error("matched expression not reported")
	}
}

func TestMatcherEmptyStore(t *testing.T) {
	if v := New(lc).Lookup("http://anything/"); v.Verdict != Clean {
		t.Errorf("empty store not Clean: %+v", v)
	}
}

func TestMatcherCanonReject(t *testing.T) {
	m := New(func(string) (string, bool) { return "", false })
	m.Install(listing("evil.com/"))
	if v := m.Lookup("http://evil.com/"); v.Verdict != Clean {
		t.Errorf("uncanonicalizable input should be Clean: %+v", v)
	}
}

func TestMatcherNilCanon(t *testing.T) {
	m := New(nil) // input treated as already canonical
	m.Install(listing("evil.com/"))
	if v := m.Lookup("evil.com/x"); !v.IsListed() {
		t.Errorf("nil canon should treat input as canonical: %+v", v)
	}
}

func TestMatcherApplyDelta(t *testing.T) {
	m := New(nil)
	base := listing("evil.com/")
	m.Install(base)
	adds := []Hash{HashURL("bad.com/")}
	want := NewSnapshot(base.Header.Profile, base.Header.Expander, base.Header.IDNA, 2, combine(base.Hashes, adds, nil))
	d := &Delta{Base: base.Header.SetHash, Target: want.Header.SetHash, Epoch: 2, Adds: adds}
	if err := m.ApplyDelta(d); err != nil {
		t.Fatalf("ApplyDelta: %v", err)
	}
	if !m.Lookup("bad.com/x").IsListed() {
		t.Error("delta-added entry not queryable after ApplyDelta")
	}
}

func TestVerdictString(t *testing.T) {
	for v, want := range map[Verdict]string{Clean: "clean", Listed: "listed"} {
		if v.String() != want {
			t.Errorf("Verdict(%d).String() = %q, want %q", v, v.String(), want)
		}
	}
}
