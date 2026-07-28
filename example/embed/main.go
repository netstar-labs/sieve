// Command embed shows sieve used as a library: build a tiny dataset, install it,
// and run a few lookups. Run: go run ./example/embed
package main

import (
	"fmt"

	"github.com/netstar-labs/sieve"
)

func main() {
	// A dataset lists canonical expressions. Here we list a whole host and one
	// exact path (production hashes come from the canonicalizer + build tool).
	hashes := []sieve.Hash{
		sieve.HashURL("evil.example/"),      // the whole host
		sieve.HashURL("shop.test/checkout"), // one exact path
	}
	snap := sieve.NewSnapshot("url/1", "expr/1", "idna:15.0.0", 1, hashes)

	m := sieve.New(nil) // nil canon: inputs are already canonical here
	m.Install(snap)

	for _, u := range []string{
		"evil.example/anything/at/all", // host-suffix match → listed
		"shop.test/checkout",           // exact match → listed
		"shop.test/browse",             // sibling path → clean
		"good.example/",                // unrelated host → clean
	} {
		v := m.Lookup(u)
		fmt.Printf("%-8s %-30s", v.Verdict, u)
		if v.IsListed() {
			fmt.Printf("  matched %q", v.Expression)
		}
		fmt.Println()
	}
}
