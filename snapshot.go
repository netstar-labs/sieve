package sieve

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"slices"
)

const (
	snapVersion  = 1
	maxFieldLen  = 4096    // stamp string cap — enforced on both encode and decode
	maxSnapCount = 1 << 30 // sanity ceiling on entry count; the fetch io.LimitReader is the operational OOM guard
)

var snapMagic = [4]byte{'S', 'I', 'E', 'V'}

// Decode errors. All decode failures are returned, never panicked.
var (
	ErrBadMagic  = errors.New("sieve: bad snapshot magic")
	ErrVersion   = errors.New("sieve: unsupported snapshot version")
	ErrFieldLen  = errors.New("sieve: snapshot field too large")
	ErrTooLarge  = errors.New("sieve: snapshot count over limit")
	ErrTruncated = errors.New("sieve: truncated snapshot")
	ErrNotSorted = errors.New("sieve: snapshot hashes not strictly increasing")
	ErrChecksum  = errors.New("sieve: snapshot checksum mismatch")
)

// Header carries the dataset stamps a query must match: the canonicalization
// Profile, the expression Expander, and the IDNA mode. IDNA is part of the
// contract — build and query must pin the same one or Unicode-host hashes silently
// won't match (a blocklist false-negative), so it travels in the header.
type Header struct {
	Version  uint8
	Profile  string
	Expander string
	IDNA     string
	Epoch    uint64
	Count    uint32
	SetHash  [32]byte // datasetHash of Hashes — the identity and the delta anchor
}

// Snapshot is an immutable reputation dataset: sorted, deduped full hashes plus a
// stamped header. Distributed whole; evolved by [Delta].
type Snapshot struct {
	Header Header
	Hashes []Hash // sorted strictly ascending, deduped
}

// NewSnapshot builds a snapshot from arbitrary hashes (copied, sorted, deduped)
// and stamps the dataset hash. profile/expander/idna record the canonicalization
// the entries were built under.
func NewSnapshot(profile, expander, idna string, epoch uint64, hashes []Hash) *Snapshot {
	sorted := slices.Clone(hashes)
	slices.SortFunc(sorted, func(a, b Hash) int { return bytes.Compare(a[:], b[:]) })
	sorted = slices.CompactFunc(sorted, func(a, b Hash) bool { return a == b })
	return &Snapshot{
		Header: Header{
			Version: snapVersion, Profile: profile, Expander: expander, IDNA: idna,
			Epoch: epoch, Count: uint32(len(sorted)), SetHash: datasetHash(sorted),
		},
		Hashes: sorted,
	}
}

// prefixes derives the []uint32 prefilter keys from the full hashes.
func (s *Snapshot) prefixes() []uint32 {
	ps := make([]uint32, len(s.Hashes))
	for i := range s.Hashes {
		ps[i] = Prefix(s.Hashes[i])
	}
	return ps
}

// Encode writes the snapshot wire form.
func (s *Snapshot) Encode(w io.Writer) error {
	bw := bufio.NewWriter(w)
	bw.Write(snapMagic[:])
	bw.WriteByte(snapVersion)
	for _, f := range []string{s.Header.Profile, s.Header.Expander, s.Header.IDNA} {
		if len(f) > maxFieldLen {
			return ErrFieldLen
		}
		var l [2]byte
		binary.BigEndian.PutUint16(l[:], uint16(len(f)))
		bw.Write(l[:])
		bw.WriteString(f)
	}
	var num [8]byte
	binary.BigEndian.PutUint64(num[:], s.Header.Epoch)
	bw.Write(num[:])
	binary.BigEndian.PutUint32(num[:4], uint32(len(s.Hashes)))
	bw.Write(num[:4])
	bw.Write(s.Header.SetHash[:])
	for i := range s.Hashes {
		bw.Write(s.Hashes[i][:])
	}
	return bw.Flush()
}

// Decode parses a snapshot from an untrusted reader. It bounds every allocation,
// requires strictly increasing hashes, and verifies the dataset checksum — a
// truncated, oversized, unsorted, or corrupt stream returns an error, never a
// panic or an unbounded allocation.
func Decode(r io.Reader) (*Snapshot, error) {
	br := bufio.NewReader(r)
	var magic [4]byte
	if _, err := io.ReadFull(br, magic[:]); err != nil {
		return nil, ErrTruncated
	}
	if magic != snapMagic {
		return nil, ErrBadMagic
	}
	ver, err := br.ReadByte()
	if err != nil {
		return nil, ErrTruncated
	}
	if ver != snapVersion {
		return nil, fmt.Errorf("%w: %d", ErrVersion, ver)
	}
	h := Header{Version: ver}
	if h.Profile, err = readField(br); err != nil {
		return nil, err
	}
	if h.Expander, err = readField(br); err != nil {
		return nil, err
	}
	if h.IDNA, err = readField(br); err != nil {
		return nil, err
	}
	var num [8]byte
	if _, err := io.ReadFull(br, num[:]); err != nil {
		return nil, ErrTruncated
	}
	h.Epoch = binary.BigEndian.Uint64(num[:])
	if _, err := io.ReadFull(br, num[:4]); err != nil {
		return nil, ErrTruncated
	}
	h.Count = binary.BigEndian.Uint32(num[:4])
	if h.Count > maxSnapCount {
		return nil, ErrTooLarge
	}
	if _, err := io.ReadFull(br, h.SetHash[:]); err != nil {
		return nil, ErrTruncated
	}
	hashes, err := readHashes(br, h.Count)
	if err != nil {
		return nil, err
	}
	if datasetHash(hashes) != h.SetHash {
		return nil, ErrChecksum
	}
	return &Snapshot{Header: h, Hashes: hashes}, nil
}

// readHashes reads exactly count strictly-increasing 32-byte hashes with bounded
// allocation: the capacity hint is capped, so a lying huge count cannot
// pre-allocate — the slice grows only with bytes actually read, and a short
// stream trips ErrTruncated. Shared by snapshot and delta decoding.
func readHashes(br *bufio.Reader, count uint32) ([]Hash, error) {
	if count > maxSnapCount {
		return nil, ErrTooLarge
	}
	out := make([]Hash, 0, min(int(count), 1<<16))
	var prev Hash
	for i := uint32(0); i < count; i++ {
		var h Hash
		if _, err := io.ReadFull(br, h[:]); err != nil {
			return nil, ErrTruncated
		}
		if i > 0 && bytes.Compare(h[:], prev[:]) <= 0 {
			return nil, ErrNotSorted // catches both unsorted and duplicate
		}
		out = append(out, h)
		prev = h
	}
	return out, nil
}

func readField(br *bufio.Reader) (string, error) {
	var l [2]byte
	if _, err := io.ReadFull(br, l[:]); err != nil {
		return "", ErrTruncated
	}
	n := binary.BigEndian.Uint16(l[:])
	if int(n) > maxFieldLen {
		return "", ErrFieldLen
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(br, buf); err != nil {
		return "", ErrTruncated
	}
	return string(buf), nil
}
