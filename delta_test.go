package sieve

import (
	"bytes"
	"errors"
	"testing"
)

// combine independently computes (base \ removes) ∪ adds — the expected delta result.
func combine(base, adds, removes []Hash) []Hash {
	rm := make(map[Hash]bool, len(removes))
	for _, h := range removes {
		rm[h] = true
	}
	set := make(map[Hash]bool)
	for _, h := range base {
		if !rm[h] {
			set[h] = true
		}
	}
	for _, h := range adds {
		set[h] = true
	}
	out := make([]Hash, 0, len(set))
	for h := range set {
		out = append(out, h)
	}
	return out
}

func TestDeltaApply(t *testing.T) {
	base := NewSnapshot("p", "e", "i", 1, hashN(10))
	adds := []Hash{HashURL("add-a"), HashURL("add-b")}
	removes := []Hash{base.Hashes[0], base.Hashes[1]}
	want := NewSnapshot("p", "e", "i", 2, combine(base.Hashes, adds, removes))

	d := &Delta{
		Base: base.Header.SetHash, Target: want.Header.SetHash,
		Profile: "p", Expander: "e", IDNA: "i",
		Epoch: 2, Adds: adds, Removes: removes,
	}
	got, err := d.Apply(base)
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if got.Header.SetHash != want.Header.SetHash {
		t.Error("result set hash != declared target")
	}
	if got.Header.Epoch != 2 {
		t.Errorf("epoch = %d, want 2", got.Header.Epoch)
	}
	if got.Header.Count != want.Header.Count {
		t.Errorf("count = %d, want %d", got.Header.Count, want.Header.Count)
	}
}

func TestDeltaWrongBase(t *testing.T) {
	base := NewSnapshot("p", "e", "i", 1, hashN(5))
	d := &Delta{Base: [32]byte{0xAA}, Target: base.Header.SetHash, Epoch: 2}
	if _, err := d.Apply(base); !errors.Is(err, ErrBase) {
		t.Errorf("got %v, want ErrBase", err)
	}
}

func TestDeltaConvergeFail(t *testing.T) {
	base := NewSnapshot("p", "e", "i", 1, hashN(5))
	d := &Delta{
		Base: base.Header.SetHash, Target: [32]byte{0x99},
		Profile: "p", Expander: "e", IDNA: "i",
		Epoch: 2, Adds: []Hash{HashURL("x")},
	}
	if _, err := d.Apply(base); !errors.Is(err, ErrConverge) {
		t.Errorf("got %v, want ErrConverge", err)
	}
}

// A delta computed against a snapshot built under a different canonicalization
// profile must be refused, not silently applied with the wrong stamp — this is
// the one failure mode Base/Target hash convergence cannot detect on its own,
// since datasetHash is purely a function of hash bytes.
func TestDeltaStampMismatch(t *testing.T) {
	base := NewSnapshot("url/1", "expr/1", "idna:15.0.0", 1, hashN(5))
	want := NewSnapshot("url/2", "expr/1", "idna:15.0.0", 2, base.Hashes)
	d := &Delta{
		Base: base.Header.SetHash, Target: want.Header.SetHash,
		Profile: "url/2", Expander: "expr/1", IDNA: "idna:15.0.0", // target's stamps, differ from base's
		Epoch: 2,
	}
	if _, err := d.Apply(base); !errors.Is(err, ErrStampMismatch) {
		t.Errorf("got %v, want ErrStampMismatch", err)
	}
}

func TestDeltaRoundTrip(t *testing.T) {
	d := &Delta{
		Base:     [32]byte{1, 2, 3},
		Target:   [32]byte{4, 5, 6},
		Profile:  "url/1",
		Expander: "expr/1",
		IDNA:     "idna:15.0.0",
		Epoch:    9,
		Adds:     []Hash{HashURL("a"), HashURL("b")},
		Removes:  []Hash{HashURL("c")},
	}
	var buf bytes.Buffer
	if err := d.Encode(&buf); err != nil {
		t.Fatal(err)
	}
	got, err := DecodeDelta(&buf)
	if err != nil {
		t.Fatalf("DecodeDelta: %v", err)
	}
	if got.Base != d.Base || got.Target != d.Target || got.Epoch != d.Epoch {
		t.Error("header mismatch")
	}
	if got.Profile != d.Profile || got.Expander != d.Expander || got.IDNA != d.IDNA {
		t.Errorf("stamp mismatch: got %+v", got)
	}
	if len(got.Adds) != 2 || len(got.Removes) != 1 {
		t.Fatalf("adds=%d removes=%d", len(got.Adds), len(got.Removes))
	}
}

func TestDecodeDeltaRejectsBadMagic(t *testing.T) {
	if _, err := DecodeDelta(bytes.NewReader([]byte("XXXX\x01"))); !errors.Is(err, ErrBadMagic) {
		t.Errorf("got %v, want ErrBadMagic", err)
	}
}
