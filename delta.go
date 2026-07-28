package sieve

import (
	"bufio"
	"encoding/binary"
	"errors"
	"io"
	"slices"
)

const deltaVersion = 1

var deltaMagic = [4]byte{'S', 'I', 'V', 'D'}

var (
	ErrBase     = errors.New("sieve: delta base does not match the snapshot")
	ErrConverge = errors.New("sieve: delta result does not hash to the declared target")
)

// Delta evolves one snapshot into the next: remove Removes, add Adds, restamp the
// epoch. It is anchored at both ends — Base pins the snapshot it applies to and
// Target pins the result — so applying to the wrong base is rejected and the
// result is self-verifying (it must hash to Target). Deletion is why the prefilter
// is a cuckoo, not a Bloom, filter.
type Delta struct {
	Base    [32]byte
	Target  [32]byte
	Epoch   uint64
	Adds    []Hash // sorted strictly ascending
	Removes []Hash // sorted strictly ascending
}

// Apply produces the target snapshot from base, carrying base's stamps and the
// delta's epoch. It refuses a mismatched base and refuses a result that does not
// hash to Target, so a corrupt or misapplied delta can never silently diverge the
// dataset.
func (d *Delta) Apply(base *Snapshot) (*Snapshot, error) {
	if base.Header.SetHash != d.Base {
		return nil, ErrBase
	}
	set := make(map[Hash]struct{}, len(base.Hashes)+len(d.Adds))
	for _, h := range base.Hashes {
		set[h] = struct{}{}
	}
	for _, h := range d.Removes {
		delete(set, h)
	}
	for _, h := range d.Adds { // adds win over removes for the same hash
		set[h] = struct{}{}
	}
	hashes := make([]Hash, 0, len(set))
	for h := range set {
		hashes = append(hashes, h)
	}
	next := NewSnapshot(base.Header.Profile, base.Header.Expander, base.Header.IDNA, d.Epoch, hashes)
	if next.Header.SetHash != d.Target {
		return nil, ErrConverge
	}
	return next, nil
}

// Encode writes the delta wire form (adds and removes each sorted+deduped).
func (d *Delta) Encode(w io.Writer) error {
	adds := sortedDedup(d.Adds)
	removes := sortedDedup(d.Removes)
	bw := bufio.NewWriter(w)
	bw.Write(deltaMagic[:])
	bw.WriteByte(deltaVersion)
	bw.Write(d.Base[:])
	bw.Write(d.Target[:])
	var num [8]byte
	binary.BigEndian.PutUint64(num[:], d.Epoch)
	bw.Write(num[:])
	binary.BigEndian.PutUint32(num[:4], uint32(len(adds)))
	bw.Write(num[:4])
	binary.BigEndian.PutUint32(num[:4], uint32(len(removes)))
	bw.Write(num[:4])
	for i := range adds {
		bw.Write(adds[i][:])
	}
	for i := range removes {
		bw.Write(removes[i][:])
	}
	return bw.Flush()
}

// DecodeDelta parses a delta from an untrusted reader with the same bounded,
// strictly-increasing discipline as [Decode].
func DecodeDelta(r io.Reader) (*Delta, error) {
	br := bufio.NewReader(r)
	var magic [4]byte
	if _, err := io.ReadFull(br, magic[:]); err != nil {
		return nil, ErrTruncated
	}
	if magic != deltaMagic {
		return nil, ErrBadMagic
	}
	ver, err := br.ReadByte()
	if err != nil {
		return nil, ErrTruncated
	}
	if ver != deltaVersion {
		return nil, ErrVersion
	}
	d := &Delta{}
	if _, err := io.ReadFull(br, d.Base[:]); err != nil {
		return nil, ErrTruncated
	}
	if _, err := io.ReadFull(br, d.Target[:]); err != nil {
		return nil, ErrTruncated
	}
	var num [8]byte
	if _, err := io.ReadFull(br, num[:]); err != nil {
		return nil, ErrTruncated
	}
	d.Epoch = binary.BigEndian.Uint64(num[:])
	nAdd, err := readCount(br)
	if err != nil {
		return nil, err
	}
	nRem, err := readCount(br)
	if err != nil {
		return nil, err
	}
	if d.Adds, err = readHashes(br, nAdd); err != nil {
		return nil, err
	}
	if d.Removes, err = readHashes(br, nRem); err != nil {
		return nil, err
	}
	return d, nil
}

func readCount(br *bufio.Reader) (uint32, error) {
	var b [4]byte
	if _, err := io.ReadFull(br, b[:]); err != nil {
		return 0, ErrTruncated
	}
	return binary.BigEndian.Uint32(b[:]), nil
}

func sortedDedup(hs []Hash) []Hash {
	out := slices.Clone(hs)
	slices.SortFunc(out, compareHash)
	return slices.CompactFunc(out, func(a, b Hash) bool { return a == b })
}
