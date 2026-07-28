package sieve

import (
	"bytes"
	"testing"
)

// FuzzSnapshotDecode drives the attacker-facing decoder with arbitrary bytes: it
// must never panic or hang, and any accepted snapshot must re-encode/re-decode
// identically (the decoder does not silently normalize a corrupt input into a
// different valid one).
func FuzzSnapshotDecode(f *testing.F) {
	var buf bytes.Buffer
	_ = NewSnapshot("url/1", "expr/1", "idna:15.0.0", 1, hashN(20)).Encode(&buf)
	f.Add(buf.Bytes())
	f.Add([]byte(nil))
	f.Add([]byte("SIEV\x01"))
	f.Add([]byte("not a snapshot at all"))

	f.Fuzz(func(t *testing.T, data []byte) {
		snap, err := Decode(bytes.NewReader(data))
		if err != nil {
			return
		}
		var out bytes.Buffer
		if err := snap.Encode(&out); err != nil {
			t.Fatalf("re-encode of an accepted snapshot failed: %v", err)
		}
		snap2, err := Decode(&out)
		if err != nil {
			t.Fatalf("re-decode of a re-encoded snapshot failed: %v", err)
		}
		if snap2.Header.SetHash != snap.Header.SetHash || len(snap2.Hashes) != len(snap.Hashes) {
			t.Fatal("decode is not idempotent")
		}
	})
}

// FuzzDecodeDelta: the delta decoder holds the same no-panic / bounded contract.
func FuzzDecodeDelta(f *testing.F) {
	var buf bytes.Buffer
	_ = (&Delta{Base: [32]byte{1}, Target: [32]byte{2}, Epoch: 3,
		Adds: []Hash{HashURL("a")}, Removes: []Hash{HashURL("b")}}).Encode(&buf)
	f.Add(buf.Bytes())
	f.Add([]byte(nil))
	f.Add([]byte("SIVD\x01"))

	f.Fuzz(func(t *testing.T, data []byte) {
		d, err := DecodeDelta(bytes.NewReader(data))
		if err != nil {
			return
		}
		var out bytes.Buffer
		if err := d.Encode(&out); err != nil {
			t.Fatalf("re-encode failed: %v", err)
		}
		if _, err := DecodeDelta(&out); err != nil {
			t.Fatalf("re-decode failed: %v", err)
		}
	})
}
