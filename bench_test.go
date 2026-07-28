package sieve

import (
	"bytes"
	"testing"
)

func BenchmarkLookupMiss(b *testing.B) {
	m := New(lc)
	m.Install(NewSnapshot("p", "e", "i", 1, hashN(100000)))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		m.Lookup("http://unlisted.example.org/some/deep/path?q=1")
	}
}

func BenchmarkLookupHit(b *testing.B) {
	m := New(lc)
	m.Install(listing("evil.com/"))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		m.Lookup("http://evil.com/a/b/c")
	}
}

func BenchmarkExpand(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		Expand("http://a.b.example.com/x/y/z?q=1")
	}
}

func BenchmarkSetContains(b *testing.B) {
	snap := NewSnapshot("p", "e", "i", 1, hashN(100000))
	set := NewSet(snap.prefixes())
	x := set.keysRef()[len(set.keysRef())/2]
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		set.Contains(x)
	}
}

func BenchmarkSnapshotDecode(b *testing.B) {
	var buf bytes.Buffer
	if err := NewSnapshot("p", "e", "i", 1, hashN(10000)).Encode(&buf); err != nil {
		b.Fatal(err)
	}
	data := buf.Bytes()
	b.ReportAllocs()
	b.SetBytes(int64(len(data)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := Decode(bytes.NewReader(data)); err != nil {
			b.Fatal(err)
		}
	}
}
