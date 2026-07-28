package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/netstar-labs/sieve"
)

func TestCLIRoundTrip(t *testing.T) {
	dir := t.TempDir()
	write := func(name, body string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
		return p
	}

	list := write("list.txt", "evil.com/\nexample.com/bad\n# a comment\n\n")
	snapA := filepath.Join(dir, "a.snap")
	if rc := run([]string{"build", "-o", snapA, "-profile", "url/1", "-idna", "idna:15.0.0", list}); rc != 0 {
		t.Fatalf("build rc=%d", rc)
	}
	if rc := run([]string{"query", "-snap", snapA, "http://example.com/bad", "http://good.com/"}); rc != 0 {
		t.Fatalf("query rc=%d", rc)
	}

	// build a second dataset, diff to a delta, apply it, and confirm the applied
	// result matches the target dataset exactly.
	list2 := write("list2.txt", "evil.com/\nexample.com/bad\nnew.com/\n")
	snapB := filepath.Join(dir, "b.snap")
	if rc := run([]string{"build", "-o", snapB, "-profile", "url/1", "-idna", "idna:15.0.0", list2}); rc != 0 {
		t.Fatalf("build2 rc=%d", rc)
	}
	delta := filepath.Join(dir, "d.delta")
	if rc := run([]string{"diff", "-base", snapA, "-target", snapB, "-o", delta}); rc != 0 {
		t.Fatalf("diff rc=%d", rc)
	}
	out := filepath.Join(dir, "out.snap")
	if rc := run([]string{"apply", "-snap", snapA, "-delta", delta, "-o", out}); rc != 0 {
		t.Fatalf("apply rc=%d", rc)
	}

	got := decode(t, out)
	want := decode(t, snapB)
	if got.Header.SetHash != want.Header.SetHash {
		t.Error("applied delta did not reproduce the target dataset")
	}
}

func TestCLIUsageAndErrors(t *testing.T) {
	if rc := run(nil); rc != 2 {
		t.Errorf("no args rc=%d, want 2", rc)
	}
	if rc := run([]string{"bogus"}); rc != 2 {
		t.Errorf("unknown command rc=%d, want 2", rc)
	}
	if rc := run([]string{"build"}); rc != 1 {
		t.Errorf("build without -o rc=%d, want 1", rc)
	}
}

func decode(t *testing.T, path string) *sieve.Snapshot {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	s, err := sieve.Decode(f)
	if err != nil {
		t.Fatal(err)
	}
	return s
}
