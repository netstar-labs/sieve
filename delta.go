package sieve

import (
	"bufio"
	"encoding/binary"
	"errors"
	"io"
	"slices"
)

const deltaVersion = 2

var deltaMagic = [4]byte{'S', 'I', 'V', 'D'}

var (
	ErrBase          = errors.New("sieve: delta base does not match the snapshot")
	ErrConverge      = errors.New("sieve: delta result does not hash to the declared target")
	ErrStampMismatch = errors.New("sieve: delta's canonicalization stamp does not match the base snapshot")
)

// Delta evolves one snapshot into the next: remove Removes, add Adds, restamp the
// epoch. It is anchored at both ends — Base pins the snapshot it applies to and
// Target pins the result — so applying to the wrong base is rejected and the
// result is self-verifying (it must hash to Target).
//
// Profile/Expander/IDNA are the TARGET snapshot's canonicalization stamps (the
// ones diff read from the snapshot the delta was computed against, not from
// base). Apply refuses to proceed if they don't match base's current stamps —
// SetHash/datasetHash is purely a function of hash bytes, so the existing
// Base/Target convergence checks cannot by themselves detect a canonicalization-
// profile change; without these fields (and this check) a delta computed across
// a profile bump would apply cleanly and produce a snapshot whose header lies
// about which scheme produced its hashes, defeating the package's own
// documented "no silent drift" guarantee — including via the ordinary
// fetch-and-apply path, which never otherwise sees the target snapshot at all.
type Delta struct {
	Base     [32]byte
	Target   [32]byte
	Profile  string
	Expander string
	IDNA     string
	Epoch    uint64
	Adds     []Hash // sorted strictly ascending
	Removes  []Hash // sorted strictly ascending
}

// Apply produces the target snapshot from base, carrying base's stamps and the
// delta's epoch. It refuses a mismatched base, refuses a result that does not
// hash to Target, and refuses a delta whose recorded canonicalization stamp
// doesn't match base's — so a corrupt, misapplied, or cross-profile delta can
// never silently diverge the dataset.
func (d *Delta) Apply(base *Snapshot) (*Snapshot, error) {
	if base.Header.SetHash != d.Base {
		return nil, ErrBase
	}
	if d.Profile != base.Header.Profile || d.Expander != base.Header.Expander || d.IDNA != base.Header.IDNA {
		return nil, ErrStampMismatch
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
	for _, f := range []string{d.Profile, d.Expander, d.IDNA} {
		if len(f) > maxFieldLen {
			return ErrFieldLen
		}
		var l [2]byte
		binary.BigEndian.PutUint16(l[:], uint16(len(f)))
		bw.Write(l[:])
		bw.WriteString(f)
	}
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
	if err := readExact(br, magic[:]); err != nil {
		return nil, err
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
	if err := readExact(br, d.Base[:]); err != nil {
		return nil, err
	}
	if err := readExact(br, d.Target[:]); err != nil {
		return nil, err
	}
	if d.Profile, err = readField(br); err != nil {
		return nil, err
	}
	if d.Expander, err = readField(br); err != nil {
		return nil, err
	}
	if d.IDNA, err = readField(br); err != nil {
		return nil, err
	}
	if d.Epoch, err = readUint64(br); err != nil {
		return nil, err
	}
	nAdd, err := readUint32(br)
	if err != nil {
		return nil, err
	}
	nRem, err := readUint32(br)
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

func sortedDedup(hs []Hash) []Hash {
	out := slices.Clone(hs)
	slices.SortFunc(out, compareHash)
	return slices.CompactFunc(out, func(a, b Hash) bool { return a == b })
}
