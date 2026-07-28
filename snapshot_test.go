package sieve

import (
	"bytes"
	"encoding/binary"
	"errors"
	"testing"
)

func TestSnapshotRoundTrip(t *testing.T) {
	snap := NewSnapshot("url/1", "expr/1", "idna:15.0.0", 7, hashN(100))
	var buf bytes.Buffer
	if err := snap.Encode(&buf); err != nil {
		t.Fatalf("Encode: %v", err)
	}
	got, err := Decode(&buf)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if got.Header != snap.Header {
		t.Errorf("header mismatch\n got %+v\nwant %+v", got.Header, snap.Header)
	}
	if len(got.Hashes) != len(snap.Hashes) {
		t.Fatalf("count = %d, want %d", len(got.Hashes), len(snap.Hashes))
	}
	for i := range got.Hashes {
		if got.Hashes[i] != snap.Hashes[i] {
			t.Fatalf("hash[%d] mismatch", i)
		}
	}
}

func TestDecodeRejectsCorruption(t *testing.T) {
	var buf bytes.Buffer
	if err := NewSnapshot("p", "e", "i", 1, hashN(10)).Encode(&buf); err != nil {
		t.Fatal(err)
	}
	good := buf.Bytes()

	cases := []struct {
		name string
		mut  func([]byte) []byte
		want error
	}{
		{"bad magic", func(b []byte) []byte { c := cloneBytes(b); c[0] ^= 0xFF; return c }, ErrBadMagic},
		{"bad version", func(b []byte) []byte { c := cloneBytes(b); c[4] = 99; return c }, ErrVersion},
		{"truncated tail", func(b []byte) []byte { return cloneBytes(b[:len(b)-5]) }, ErrTruncated},
		{"empty", func(b []byte) []byte { return nil }, ErrTruncated},
		{"bad checksum", func(b []byte) []byte { c := cloneBytes(b); c[len(c)-1] ^= 0x01; return c }, ErrChecksum},
	}
	for _, tc := range cases {
		if _, err := Decode(bytes.NewReader(tc.mut(good))); !errors.Is(err, tc.want) {
			t.Errorf("%s: got %v, want %v", tc.name, err, tc.want)
		}
	}
}

func TestDecodeOversizeCount(t *testing.T) {
	// A header claiming more entries than the ceiling must be rejected before any
	// body allocation.
	var b []byte
	b = append(b, snapMagic[:]...)
	b = append(b, snapVersion)
	b = append(b, 0, 0, 0, 0, 0, 0) // three empty stamp fields
	b = append(b, make([]byte, 8)...)
	var c [4]byte
	binary.BigEndian.PutUint32(c[:], 0xFFFFFFFF)
	b = append(b, c[:]...)
	b = append(b, make([]byte, 32)...) // setHash
	if _, err := Decode(bytes.NewReader(b)); !errors.Is(err, ErrTooLarge) {
		t.Errorf("got %v, want ErrTooLarge", err)
	}
}

func TestDecodeNonMonotonic(t *testing.T) {
	var buf bytes.Buffer
	if err := NewSnapshot("p", "e", "i", 1, hashN(2)).Encode(&buf); err != nil {
		t.Fatal(err)
	}
	b := buf.Bytes()
	// swap the two trailing 32-byte hashes -> descending -> not strictly increasing
	n := len(b)
	swapped := cloneBytes(b)
	copy(swapped[n-64:n-32], b[n-32:])
	copy(swapped[n-32:], b[n-64:n-32])
	if _, err := Decode(bytes.NewReader(swapped)); !errors.Is(err, ErrNotSorted) {
		t.Errorf("got %v, want ErrNotSorted", err)
	}
}

func TestDecodeFieldTooLarge(t *testing.T) {
	var b []byte
	b = append(b, snapMagic[:]...)
	b = append(b, snapVersion)
	var l [2]byte
	binary.BigEndian.PutUint16(l[:], maxFieldLen+1) // over the cap
	b = append(b, l[:]...)
	if _, err := Decode(bytes.NewReader(b)); !errors.Is(err, ErrFieldLen) {
		t.Errorf("got %v, want ErrFieldLen", err)
	}
}
