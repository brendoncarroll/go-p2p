package p2pkeswarm

import (
	"sync"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/exp/constraints"

	"github.com/brendoncarroll/go-p2p"
	"github.com/brendoncarroll/go-p2p/p2ptest"
	"github.com/brendoncarroll/go-p2p/s/memswarm"
	"github.com/brendoncarroll/go-p2p/s/swarmtest"
	"github.com/brendoncarroll/go-p2p/s/udpswarm"
)

func testSwarm[T ComparableAddr](t *testing.T, baseSwarms func(testing.TB, []p2p.Swarm[T])) {
	swarmtest.TestSwarm(t, func(t testing.TB, xs []p2p.Swarm[Addr[T]]) {
		ss := make([]p2p.Swarm[T], len(xs))
		baseSwarms(t, ss)
		for i := range xs {
			privKey := p2ptest.NewTestKey(t, i)
			s := New(ss[i], privKey)
			xs[i] = s
		}
		t.Cleanup(func() { swarmtest.CloseSwarms(t, xs) })
	})
	swarmtest.TestSecureSwarm(t, func(t testing.TB, xs []p2p.SecureSwarm[Addr[T]]) {
		ss := make([]p2p.Swarm[T], len(xs))
		baseSwarms(t, ss)
		for i := range xs {
			privKey := p2ptest.NewTestKey(t, i)
			s := New(ss[i], privKey)
			xs[i] = s
		}
		t.Cleanup(func() { swarmtest.CloseSecureSwarms(t, xs) })
	})
}

func TestOnUDP(t *testing.T) {
	t.Parallel()
	testSwarm(t, func(t testing.TB, xs []p2p.Swarm[udpswarm.Addr]) {
		for i := range xs {
			var err error
			xs[i], err = udpswarm.New("127.0.0.1:")
			require.NoError(t, err)
		}
	})
}

func TestOnMem(t *testing.T) {
	t.Parallel()
	testSwarm(t, func(t testing.TB, xs []p2p.Swarm[memswarm.Addr]) {
		var opts []memswarm.Option
		// opts = append(opts, memswarm.WithLogging(os.Stdout))
		r := memswarm.NewRealm(opts...)
		for i := range xs {
			xs[i] = r.NewSwarm()
		}
	})
}

func TestOnDropFirst(t *testing.T) {
	t.Parallel()
	testSwarm(t, func(t testing.TB, xs []p2p.Swarm[memswarm.Addr]) {
		var opts []memswarm.Option
		opts = append(opts, memswarm.WithTellTransform(newDropFirst(t)))
		r := memswarm.NewRealm(opts...)
		for i := range xs {
			xs[i] = r.NewSwarm()
		}
	})
}

func newDropFirst(t testing.TB) func(memswarm.Message) *memswarm.Message {
	type FlowID [2]int
	var mu sync.Mutex
	m := map[FlowID]struct{}{}
	return func(x memswarm.Message) *memswarm.Message {
		flowID := [2]int{min(x.Src.N, x.Dst.N), max(x.Src.N, x.Dst.N)}
		mu.Lock()
		defer mu.Unlock()
		if _, exists := m[flowID]; exists {
			return &x
		}
		m[flowID] = struct{}{}
		return nil
	}
}

func min[T constraints.Ordered](xs ...T) (ret T) {
	if len(xs) > 0 {
		ret = xs[0]
	}
	for i := range xs {
		if xs[i] < ret {
			ret = xs[i]
		}
	}
	return ret
}

func max[T constraints.Ordered](xs ...T) (ret T) {
	if len(xs) > 0 {
		ret = xs[0]
	}
	for i := range xs {
		if xs[i] > ret {
			ret = xs[i]
		}
	}
	return ret
}
