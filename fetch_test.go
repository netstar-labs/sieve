package sieve

import (
	"bytes"
	"crypto/sha256"
	"crypto/tls"
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

// The TLS floor is an invariant, not an incidental. sieve is one of five
// pinned-TLS clients in the org and was the only one without a stated minimum;
// the four others drifted apart on exactly these fields precisely because
// nothing asserted them. This is the guard rail, not the fix.
func TestHTTPClientPinsTLSFloor(t *testing.T) {
	for name, c := range map[string]*Client{
		"no pin":   {BaseURL: "https://feeds.nsgrid.co"},
		"with pin": {BaseURL: "https://feeds.nsgrid.co", PinSHA256: [32]byte{1}},
	} {
		t.Run(name, func(t *testing.T) {
			tr, ok := c.httpClient().Transport.(*http.Transport)
			if !ok {
				t.Fatalf("transport is %T, want *http.Transport", c.httpClient().Transport)
			}
			if tr.TLSClientConfig == nil {
				t.Fatal("no TLSClientConfig: the floor would be whatever the toolchain defaults to")
			}
			if got := tr.TLSClientConfig.MinVersion; got != tls.VersionTLS13 {
				t.Errorf("MinVersion = %#x, want TLS 1.3 (%#x). If a publisher genuinely "+
					"cannot do 1.3, lower it in fetch.go AND name the publisher there — do not "+
					"just relax this test", got, tls.VersionTLS13)
			}
		})
	}
}

// A caller-supplied HTTP client is used as given: sieve must not silently
// rewrite someone else's transport, and must not be assumed to have pinned
// anything on their behalf.
func TestSuppliedHTTPClientIsUsedVerbatim(t *testing.T) {
	mine := &http.Client{}
	c := &Client{BaseURL: "https://feeds.nsgrid.co", HTTP: mine}
	if got := c.httpClient(); got != mine {
		t.Fatal("a caller-supplied HTTP client was replaced")
	}
}

// Without a pin, chain validation must stay ON — the zero PinSHA256 is a
// public-feed affordance, not a licence to skip verification.
func TestNoPinKeepsChainValidation(t *testing.T) {
	c := &Client{BaseURL: "https://feeds.nsgrid.co"}
	tr := c.httpClient().Transport.(*http.Transport)
	if tr.TLSClientConfig.InsecureSkipVerify {
		t.Fatal("InsecureSkipVerify is on with no pin: nothing would authenticate the server")
	}
	if tr.TLSClientConfig.VerifyPeerCertificate != nil {
		t.Fatal("a verify callback is set with no pin; the zero pin must mean ordinary chain trust")
	}

	// With a pin, the inverse: the pin replaces chain trust.
	p := &Client{BaseURL: "https://feeds.nsgrid.co", PinSHA256: [32]byte{1}}
	ptr := p.httpClient().Transport.(*http.Transport)
	if !ptr.TLSClientConfig.InsecureSkipVerify {
		t.Fatal("with a pin, InsecureSkipVerify must be on — it is what routes the leaf to the pinner")
	}
	if ptr.TLSClientConfig.VerifyPeerCertificate == nil {
		t.Fatal("with a pin, InsecureSkipVerify is on and NOTHING verifies: accepts any peer")
	}
}
