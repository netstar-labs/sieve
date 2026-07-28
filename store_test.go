package sieve

import (
	"errors"
	"sync"
	"testing"
)

func TestStoreApplyDelta(t *testing.T) {
	s := NewStore()
	base := NewSnapshot("p", "e", "i", 1, hashN(10))
	s.Install(base)

	adds := []Hash{HashURL("new")}
	want := NewSnapshot("p", "e", "i", 2, combine(base.Hashes, adds, nil))
	d := &Delta{Base: base.Header.SetHash, Target: want.Header.SetHash, Epoch: 2, Adds: adds}
	if err := s.ApplyDelta(d); err != nil {
		t.Fatalf("ApplyDelta: %v", err)
	}
	if got := s.current(); got.header.SetHash != want.Header.SetHash {
		t.Error("store did not swap to the delta result")
	}
}

func TestStoreApplyDeltaNoBase(t *testing.T) {
	if err := NewStore().ApplyDelta(&Delta{}); !errors.Is(err, ErrBase) {
		t.Errorf("got %v, want ErrBase on empty store", err)
	}
}

// Run with -race: lock-free reads must never observe a torn index while writers
// swap snapshots underneath them.
func TestStoreConcurrentSwap(t *testing.T) {
	s := NewStore()
	s.Install(NewSnapshot("p", "e", "i", 0, hashN(1000)))

	var wg sync.WaitGroup
	stop := make(chan struct{})
	for r := 0; r < 8; r++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
					if idx := s.current(); idx != nil {
						_ = idx.set.Contains(distinct(7))
						_ = containsHash(idx.confirm, HashURL("x"))
					}
				}
			}
		}()
	}
	for i := 0; i < 100; i++ {
		s.Install(NewSnapshot("p", "e", "i", uint64(i), hashN(1000+i)))
	}
	close(stop)
	wg.Wait()
}
