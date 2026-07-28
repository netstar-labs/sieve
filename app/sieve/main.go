// Command sieve builds, queries, diffs, and applies URL-reputation datasets.
//
//	sieve build -o SNAP [-profile P -expander E -idna I -epoch N] LISTFILE
//	sieve query -snap SNAP URL [URL...]
//	sieve diff  -base A -target B -o DELTA
//	sieve apply -snap BASE -delta DELTA -o OUT
//	sieve fetch -url URL [-pin SHA256HEX -max BYTES] -o SNAP
//
// LISTFILE is one canonical expression per line ("#" comments allowed). The tool
// hashes expressions as given; production canonicalizes with the netstar
// canonicalizer first (query here assumes already-canonical input).
package main

import (
	"bufio"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/netstar-labs/sieve"
)

func main() { os.Exit(run(os.Args[1:])) }

func run(args []string) int {
	if len(args) == 0 {
		usage()
		return 2
	}
	switch args[0] {
	case "build":
		return build(args[1:])
	case "query":
		return query(args[1:])
	case "diff":
		return diff(args[1:])
	case "apply":
		return apply(args[1:])
	case "fetch":
		return fetch(args[1:])
	default:
		usage()
		return 2
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, `sieve — URL-reputation dataset tool
  sieve build -o SNAP [-profile P -expander E -idna I -epoch N] LISTFILE
  sieve query -snap SNAP URL [URL...]
  sieve diff  -base A -target B -o DELTA
  sieve apply -snap BASE -delta DELTA -o OUT
  sieve fetch -url URL [-pin SHA256HEX -max BYTES] -o SNAP`)
}

func build(args []string) int {
	fs := flag.NewFlagSet("build", flag.ContinueOnError)
	out := fs.String("o", "", "output snapshot path (required)")
	profile := fs.String("profile", "", "canon-profile stamp")
	expander := fs.String("expander", "", "expander stamp")
	idna := fs.String("idna", "", "IDNA-mode stamp")
	epoch := fs.Uint64("epoch", 1, "dataset epoch")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *out == "" || fs.NArg() < 1 {
		return errf("build: -o and a LISTFILE are required")
	}
	f, err := os.Open(fs.Arg(0))
	if err != nil {
		return errf("build: %v", err)
	}
	defer f.Close()
	var hashes []sieve.Hash
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64*1024), 1<<20)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		hashes = append(hashes, sieve.HashURL(line))
	}
	if err := sc.Err(); err != nil {
		return errf("build: read: %v", err)
	}
	snap := sieve.NewSnapshot(*profile, *expander, *idna, *epoch, hashes)
	if err := writeFile(*out, snap.Encode); err != nil {
		return errf("build: %v", err)
	}
	fmt.Printf("built %s: %d entries, epoch %d\n", *out, snap.Header.Count, *epoch)
	return 0
}

func query(args []string) int {
	fs := flag.NewFlagSet("query", flag.ContinueOnError)
	snapPath := fs.String("snap", "", "snapshot path (required)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *snapPath == "" || fs.NArg() < 1 {
		return errf("query: -snap and at least one URL are required")
	}
	snap, err := readSnapshot(*snapPath)
	if err != nil {
		return errf("query: %v", err)
	}
	m := sieve.New(nil) // input assumed canonical; wire the netstar canonicalizer in production
	m.Install(snap)
	for _, u := range fs.Args() {
		v := m.Lookup(u)
		if v.IsListed() {
			fmt.Printf("%-8s %s  (matched %q)\n", v.Verdict, u, v.Expression)
		} else {
			fmt.Printf("%-8s %s\n", v.Verdict, u)
		}
	}
	return 0
}

func diff(args []string) int {
	fs := flag.NewFlagSet("diff", flag.ContinueOnError)
	basePath := fs.String("base", "", "base snapshot (required)")
	targetPath := fs.String("target", "", "target snapshot (required)")
	out := fs.String("o", "", "output delta path (required)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *basePath == "" || *targetPath == "" || *out == "" {
		return errf("diff: -base, -target, and -o are required")
	}
	base, err := readSnapshot(*basePath)
	if err != nil {
		return errf("diff: base: %v", err)
	}
	target, err := readSnapshot(*targetPath)
	if err != nil {
		return errf("diff: target: %v", err)
	}
	inBase := make(map[sieve.Hash]bool, len(base.Hashes))
	for _, h := range base.Hashes {
		inBase[h] = true
	}
	inTarget := make(map[sieve.Hash]bool, len(target.Hashes))
	for _, h := range target.Hashes {
		inTarget[h] = true
	}
	var adds, removes []sieve.Hash
	for _, h := range target.Hashes {
		if !inBase[h] {
			adds = append(adds, h)
		}
	}
	for _, h := range base.Hashes {
		if !inTarget[h] {
			removes = append(removes, h)
		}
	}
	d := &sieve.Delta{Base: base.Header.SetHash, Target: target.Header.SetHash, Epoch: target.Header.Epoch, Adds: adds, Removes: removes}
	if err := writeFile(*out, d.Encode); err != nil {
		return errf("diff: %v", err)
	}
	fmt.Printf("delta %s: +%d -%d\n", *out, len(adds), len(removes))
	return 0
}

func apply(args []string) int {
	fs := flag.NewFlagSet("apply", flag.ContinueOnError)
	snapPath := fs.String("snap", "", "base snapshot (required)")
	deltaPath := fs.String("delta", "", "delta (required)")
	out := fs.String("o", "", "output snapshot path (required)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *snapPath == "" || *deltaPath == "" || *out == "" {
		return errf("apply: -snap, -delta, and -o are required")
	}
	base, err := readSnapshot(*snapPath)
	if err != nil {
		return errf("apply: base: %v", err)
	}
	f, err := os.Open(*deltaPath)
	if err != nil {
		return errf("apply: delta: %v", err)
	}
	defer f.Close()
	d, err := sieve.DecodeDelta(f)
	if err != nil {
		return errf("apply: delta: %v", err)
	}
	next, err := d.Apply(base)
	if err != nil {
		return errf("apply: %v", err)
	}
	if err := writeFile(*out, next.Encode); err != nil {
		return errf("apply: %v", err)
	}
	fmt.Printf("applied %s: %d entries, epoch %d\n", *out, next.Header.Count, next.Header.Epoch)
	return 0
}

func fetch(args []string) int {
	fs := flag.NewFlagSet("fetch", flag.ContinueOnError)
	url := fs.String("url", "", "snapshot URL (required)")
	out := fs.String("o", "", "output snapshot path (required)")
	pin := fs.String("pin", "", "SPKI SHA-256 pin (64 hex chars)")
	max := fs.Int64("max", 0, "max body bytes (0 = default cap)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *url == "" || *out == "" {
		return errf("fetch: -url and -o are required")
	}
	c := &sieve.Client{BaseURL: *url, MaxBody: *max}
	if *pin != "" {
		raw, err := hex.DecodeString(*pin)
		if err != nil || len(raw) != 32 {
			return errf("fetch: -pin must be 64 hex chars (32-byte SPKI SHA-256)")
		}
		copy(c.PinSHA256[:], raw)
	}
	snap, err := c.FetchSnapshot("")
	if err != nil {
		return errf("fetch: %v", err)
	}
	if err := writeFile(*out, snap.Encode); err != nil {
		return errf("fetch: %v", err)
	}
	fmt.Printf("fetched %s: %d entries\n", *out, snap.Header.Count)
	return 0
}

func readSnapshot(path string) (*sieve.Snapshot, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return sieve.Decode(f)
}

func writeFile(path string, encode func(io.Writer) error) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	if err := encode(f); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

func errf(format string, a ...any) int {
	fmt.Fprintf(os.Stderr, format+"\n", a...)
	return 1
}
