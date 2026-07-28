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
)

// DefaultMaxBody caps a fetched snapshot/delta body. A partner-facing datashipper
// must bound the body so a hostile or broken feed cannot OOM the consumer.
const DefaultMaxBody = 1 << 30 // 1 GiB

var (
	ErrBodyTooLarge = errors.New("sieve: fetch body exceeds the size cap")
	ErrPin          = errors.New("sieve: server public key does not match the pin")
)

// Client fetches snapshots and deltas over HTTPS with the two safeguards the
// dataset format cannot provide: a body size cap (io.LimitedReader) and TLS
// public-key pinning (SPKI SHA-256 of the leaf certificate). A datashipper with
// neither is the risk the format leaves to the transport.
type Client struct {
	BaseURL   string       // e.g. https://feeds.netstar.dev
	MaxBody   int64        // 0 => DefaultMaxBody
	PinSHA256 [32]byte     // SHA-256 of the leaf cert SubjectPublicKeyInfo; zero => no pin
	HTTP      *http.Client // nil => a client built from PinSHA256
}

func (c *Client) maxBody() int64 {
	if c.MaxBody > 0 {
		return c.MaxBody
	}
	return DefaultMaxBody
}

func (c *Client) httpClient() *http.Client {
	if c.HTTP != nil {
		return c.HTTP
	}
	tc := &tls.Config{}
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
	return &http.Client{Transport: &http.Transport{TLSClientConfig: tc}}
}

// FetchSnapshot GETs and decodes a snapshot, bounding the body at MaxBody.
func (c *Client) FetchSnapshot(path string) (*Snapshot, error) {
	body, err := c.get(path)
	if err != nil {
		return nil, err
	}
	defer body.Close()
	lr := &io.LimitedReader{R: body, N: c.maxBody() + 1}
	snap, derr := Decode(lr)
	if lr.N <= 0 {
		return nil, ErrBodyTooLarge // consumed cap+1 bytes → oversized
	}
	if derr != nil {
		return nil, derr
	}
	return snap, nil
}

// FetchDelta GETs and decodes a delta, bounding the body at MaxBody.
func (c *Client) FetchDelta(path string) (*Delta, error) {
	body, err := c.get(path)
	if err != nil {
		return nil, err
	}
	defer body.Close()
	lr := &io.LimitedReader{R: body, N: c.maxBody() + 1}
	d, derr := DecodeDelta(lr)
	if lr.N <= 0 {
		return nil, ErrBodyTooLarge
	}
	if derr != nil {
		return nil, derr
	}
	return d, nil
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
