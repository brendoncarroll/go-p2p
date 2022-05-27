package p2ptest

import (
	"sync"

	"github.com/brendoncarroll/go-p2p/s/memswarm"
)

// NewDropFirstPairwise returns a Message transformer which drops the first message between each pair
// of addresses {src, dst}.
//
// NewDropFirstPairwise tracks src/dst combinations.
// NewDropFirstTuple tracks src/dst permutations.
func NewDropFirstPairwise() func(memswarm.Message) *memswarm.Message {
	type A = memswarm.Addr
	type M = memswarm.Message
	type FlowID [2]A
	var mu sync.Mutex
	m := map[FlowID]struct{}{}
	return func(x M) *M {
		flowID := FlowID{min(x.Src, x.Dst), max(x.Src, x.Dst)}
		mu.Lock()
		defer mu.Unlock()
		if _, exists := m[flowID]; exists {
			return &x
		}
		m[flowID] = struct{}{}
		return nil
	}
}

// NewDropFirstTuple returns a Message transformer which drops the first message
// for each (src, dst) tuple.
//
// NewDropFirstTuple tracks src/dst permutations.
// NewDropFirstPairwise tracks src/dst combinations.
func NewDropFirstTuple() func(memswarm.Message) *memswarm.Message {
	type A = memswarm.Addr
	type M = memswarm.Message
	type Tuple [2]A
	var mu sync.Mutex
	m := map[Tuple]struct{}{}
	return func(x M) *M {
		t := Tuple{x.Src, x.Dst}
		mu.Lock()
		defer mu.Unlock()
		if _, exists := m[t]; exists {
			return &x
		}
		m[t] = struct{}{}
		return nil
	}
}

func min(a, b memswarm.Addr) memswarm.Addr {
	if a.N < b.N {
		return a
	}
	return b
}

func max(a, b memswarm.Addr) memswarm.Addr {
	if a.N > b.N {
		return a
	}
	return b
}
