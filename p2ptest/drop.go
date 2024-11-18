package p2ptest

import (
	"sync"

	"go.brendoncarroll.net/p2p/s/memswarm"
)

// NewDropFirstPairwise returns a Message transformer which drops the first message between each pair
// of addresses {src, dst}.
//
// NewDropFirstPairwise tracks src/dst combinations.
// NewDropFirstTuple tracks src/dst permutations.
func NewDropFirstPairwise() func(*memswarm.Message) bool {
	type A = memswarm.Addr
	type M = memswarm.Message
	type FlowID [2]A
	var mu sync.Mutex
	m := map[FlowID]struct{}{}
	return func(x *M) bool {
		flowID := FlowID{min(x.Src, x.Dst), max(x.Src, x.Dst)}
		mu.Lock()
		defer mu.Unlock()
		if _, exists := m[flowID]; exists {
			return true
		}
		m[flowID] = struct{}{}
		return false
	}
}

// NewDropFirstTuple returns a Message transformer which drops the first message
// for each (src, dst) tuple.
//
// NewDropFirstTuple tracks src/dst permutations.
// NewDropFirstPairwise tracks src/dst combinations.
func NewDropFirstTuple() func(*memswarm.Message) bool {
	type A = memswarm.Addr
	type M = memswarm.Message
	type Tuple [2]A
	var mu sync.Mutex
	m := map[Tuple]struct{}{}
	return func(x *M) bool {
		t := Tuple{x.Src, x.Dst}
		mu.Lock()
		defer mu.Unlock()
		if _, exists := m[t]; exists {
			return true
		}
		m[t] = struct{}{}
		return false
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
