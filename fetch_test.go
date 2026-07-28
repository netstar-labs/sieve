package sieve

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func serveBytes(t *testing.T, body []byte) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Write(body)
	}))
}

func TestFetchSnapshot(t *testing.T) {
	var buf bytes.Buffer
	if err := NewSnapshot("p", "e", "i", 1, hashN(50)).Encode(&buf); err != nil {
		t.Fatal(err)
	}
	srv := serveBytes(t, buf.Bytes())
	defer srv.Close()
	got, err := (&Client{BaseURL: srv.URL}).FetchSnapshot("/snap")
	if err != nil {
		t.Fatalf("FetchSnapshot: %v", err)
	}
	if got.Header.Count != 50 {
		t.Errorf("count = %d, want 50", got.Header.Count)
	}
}

func TestFetchSizeCap(t *testing.T) {
	var buf bytes.Buffer
	if err := NewSnapshot("p", "e", "i", 1, hashN(1000)).Encode(&buf); err != nil { // ~32 KiB
		t.Fatal(err)
	}
	srv := serveBytes(t, buf.Bytes())
	defer srv.Close()
	_, err := (&Client{BaseURL: srv.URL, MaxBody: 1000}).FetchSnapshot("/")
	if !errors.Is(err, ErrBodyTooLarge) {
		t.Errorf("got %v, want ErrBodyTooLarge", err)
	}
}

func TestFetchNon200(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "nope", http.StatusNotFound)
	}))
	defer srv.Close()
	if _, err := (&Client{BaseURL: srv.URL}).FetchSnapshot("/"); err == nil {
		t.Error("expected an error on a 404 response")
	}
}

func TestFetchDelta(t *testing.T) {
	var buf bytes.Buffer
	d := &Delta{Base: [32]byte{1}, Target: [32]byte{2}, Epoch: 3, Adds: []Hash{HashURL("a")}}
	if err := d.Encode(&buf); err != nil {
		t.Fatal(err)
	}
	srv := serveBytes(t, buf.Bytes())
	defer srv.Close()
	got, err := (&Client{BaseURL: srv.URL}).FetchDelta("/d")
	if err != nil {
		t.Fatalf("FetchDelta: %v", err)
	}
	if got.Epoch != 3 || len(got.Adds) != 1 {
		t.Errorf("delta = %+v", got)
	}
}

// A feed that stalls the body (never finishing) must not hang the consumer: the
// client's overall deadline aborts it. Bytes are capped by MaxBody; time by Timeout.
func TestFetchTimeout(t *testing.T) {
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {
		<-release // hold the response open past the client deadline
	}))
	t.Cleanup(func() { close(release); srv.Close() })

	start := time.Now()
	_, err := (&Client{BaseURL: srv.URL, Timeout: 100 * time.Millisecond}).FetchSnapshot("/")
	if err == nil {
		t.Fatal("expected a timeout error from a stalled feed")
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Errorf("took %v — the deadline was not enforced", elapsed)
	}
}

func TestFetchTLSPin(t *testing.T) {
	var buf bytes.Buffer
	if err := NewSnapshot("p", "e", "i", 1, hashN(5)).Encode(&buf); err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Write(buf.Bytes())
	}))
	defer srv.Close()
	pin := sha256.Sum256(srv.Certificate().RawSubjectPublicKeyInfo)

	if _, err := (&Client{BaseURL: srv.URL, PinSHA256: pin}).FetchSnapshot("/"); err != nil {
		t.Fatalf("correct pin should verify: %v", err)
	}
	var wrong [32]byte
	wrong[0] = pin[0] ^ 0xFF
	if _, err := (&Client{BaseURL: srv.URL, PinSHA256: wrong}).FetchSnapshot("/"); err == nil {
		t.Error("wrong pin should fail the handshake")
	}
}
