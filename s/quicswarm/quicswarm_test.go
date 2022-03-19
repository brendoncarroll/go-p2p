package quicswarm

import (
	"testing"

	"github.com/brendoncarroll/go-p2p"
	"github.com/brendoncarroll/go-p2p/p2ptest"
	"github.com/brendoncarroll/go-p2p/s/memswarm"
	"github.com/brendoncarroll/go-p2p/s/swarmtest"
	"github.com/brendoncarroll/go-p2p/s/udpswarm"
	"github.com/stretchr/testify/require"
)

func testSwarm[T p2p.Addr](t *testing.T, baseSwarms func(testing.TB, []p2p.Swarm[T])) {
	swarmtest.TestSwarm(t, func(t testing.TB, xs []p2p.Swarm[Addr[T]]) {
		ss := make([]p2p.Swarm[T], len(xs))
		baseSwarms(t, ss)
		for i := range xs {
			privKey := p2ptest.NewTestKey(t, i)
			s, err := New(ss[i], privKey)
			require.NoError(t, err)
			xs[i] = s
		}
		t.Cleanup(func() { swarmtest.CloseSwarms(t, xs) })
	})
	swarmtest.TestAskSwarm(t, func(t testing.TB, xs []p2p.AskSwarm[Addr[T]]) {
		ss := make([]p2p.Swarm[T], len(xs))
		baseSwarms(t, ss)
		for i := range xs {
			privKey := p2ptest.NewTestKey(t, i)
			s, err := New(ss[i], privKey)
			require.NoError(t, err)
			xs[i] = s
		}
		t.Cleanup(func() { swarmtest.CloseAskSwarms(t, xs) })
	})
	swarmtest.TestSecureSwarm(t, func(t testing.TB, xs []p2p.SecureSwarm[Addr[T]]) {
		ss := make([]p2p.Swarm[T], len(xs))
		baseSwarms(t, ss)
		for i := range xs {
			privKey := p2ptest.NewTestKey(t, i)
			s, err := New(ss[i], privKey)
			require.NoError(t, err)
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
