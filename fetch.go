package sieve

import (
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"
)

// DefaultMaxBody caps a fetched snapshot/delta body. A partner-facing datashipper
// must bound the body so a hostile or broken feed cannot OOM the consumer.
const DefaultMaxBody = 1 << 30 // 1 GiB

// DefaultTimeout bounds the whole fetch (dial + handshake + body). The body cap
// limits bytes but not time; without a deadline a slow-loris feed that trickles
// the body one byte at a time would hang the consumer forever. Raise it for very
// large datasets over slow links.
const DefaultTimeout = 5 * time.Minute

var (
	ErrBodyTooLarge = errors.New("sieve: fetch body exceeds the size cap")
	ErrPin          = errors.New("sieve: server public key does not match the pin")
)

// Client fetches snapshots and deltas over HTTPS with the two safeguards the
// dataset format cannot provide: a body size cap (io.LimitedReader) and TLS
// public-key pinning (SPKI SHA-256 of the leaf certificate). A datashipper with
// neither is the risk the format leaves to the transport.
type Client struct {
	BaseURL   string        // e.g. https://feeds.nsgrid.co
	MaxBody   int64         // 0 => DefaultMaxBody
	Timeout   time.Duration // 0 => DefaultTimeout; overall per-fetch deadline
	PinSHA256 [32]byte      // SHA-256 of the leaf cert SubjectPublicKeyInfo; zero => no pin
	// HTTP is used verbatim when non-nil — which means PinSHA256 and the TLS-1.3
	// floor below are NOT applied in that case; supplying your own *http.Client
	// takes over TLS configuration entirely, including pinning. Nil builds one
	// from PinSHA256.
	HTTP *http.Client
}

func (c *Client) maxBody() int64 {
	if c.MaxBody > 0 {
		return c.MaxBody
	}
	return DefaultMaxBody
}

func (c *Client) timeout() time.Duration {
	if c.Timeout > 0 {
		return c.Timeout
	}
	return DefaultTimeout
}

func (c *Client) httpClient() *http.Client {
	if c.HTTP != nil {
		return c.HTTP
	}
	// Pin the floor rather than inherit it. An unset MinVersion is not TLS 1.0 —
	// crypto/tls already refuses anything below 1.2 (common.go, supportedVersions)
	// — but it leaves the floor implicit, so it moves if the toolchain's default
	// moves, and it made sieve the only one of the org's five pinned-TLS clients
	// without a stated minimum.
	//
	// 1.3 is verified against the endpoints this client is for, not assumed:
	// feeds.nsgrid.co and bundles.nsgrid.co each completed 12 of 12 fresh
	// TLS-1.3-only handshakes, and all three storage nodes accept 1.3-only
	// directly by IP for both SNI names. If a future publisher genuinely cannot
	// do 1.3, lower this to VersionTLS12 and name that publisher here — a bare
	// downgrade with no reason is how the floor became implicit in the first
	// place.
	tc := &tls.Config{MinVersion: tls.VersionTLS13}
	var zero [32]byte
	if c.PinSHA256 != zero {
		pin := c.PinSHA256
		// The pin replaces chain/hostname trust: verify the leaf SPKI ourselves.
		tc.InsecureSkipVerify = true
		tc.VerifyPeerCertificate = func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			if len(rawCerts) == 0 {
				return ErrPin
			}
			leaf, err := x509.ParseCertificate(rawCerts[0])
			if err != nil {
				return ErrPin
			}
			sum := sha256.Sum256(leaf.RawSubjectPublicKeyInfo)
			if subtle.ConstantTimeCompare(sum[:], pin[:]) != 1 {
				return ErrPin
			}
			return nil
		}
	}
	return &http.Client{
		Timeout:   c.timeout(),
		Transport: &http.Transport{TLSClientConfig: tc, ResponseHeaderTimeout: c.timeout()},
	}
}

// FetchSnapshot GETs and decodes a snapshot, bounding the body at MaxBody.
func (c *Client) FetchSnapshot(path string) (*Snapshot, error) {
	return fetchDecode(c, path, Decode)
}

// FetchDelta GETs and decodes a delta, bounding the body at MaxBody.
func (c *Client) FetchDelta(path string) (*Delta, error) {
	return fetchDecode(c, path, DecodeDelta)
}

// fetchDecode is the shared body-cap-and-decode plumbing: GET, bound the body at
// MaxBody+1 so an over-cap feed reliably reports ErrBodyTooLarge, and decode with
// the given decoder. Keeping it in one place means the OOM guard has a single
// implementation for both snapshots and deltas.
func fetchDecode[T any](c *Client, path string, dec func(io.Reader) (T, error)) (T, error) {
	var zero T
	body, err := c.get(path)
	if err != nil {
		return zero, err
	}
	defer body.Close()
	lr := &io.LimitedReader{R: body, N: c.maxBody() + 1}
	v, derr := dec(lr)
	if lr.N <= 0 {
		return zero, ErrBodyTooLarge // consumed cap+1 bytes → oversized
	}
	if derr != nil {
		return zero, derr
	}
	return v, nil
}

func (c *Client) get(path string) (io.ReadCloser, error) {
	resp, err := c.httpClient().Get(c.BaseURL + path)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		resp.Body.Close()
		return nil, fmt.Errorf("sieve: fetch %s: %s", path, resp.Status)
	}
	return resp.Body, nil
}
