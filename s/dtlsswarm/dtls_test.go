package dtlsswarm

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/brendoncarroll/go-p2p"
	"github.com/brendoncarroll/go-p2p/p2ptest"
	"github.com/brendoncarroll/go-p2p/s/memswarm"
	"github.com/brendoncarroll/go-p2p/s/swarmtest"
	"github.com/brendoncarroll/go-p2p/s/udpswarm"
)

func TestSuiteMem(t *testing.T) {
	t.Parallel()
	swarmtest.TestSuiteSwarm(t, func(n int, fn func(xs []p2p.Swarm)) {
		r := memswarm.NewRealm()
		//r = r.WithLogging(os.Stderr)
		xs := make([]p2p.Swarm, n)
		for i := range xs {
			u := r.NewSwarm()
			k := p2ptest.GetTestKey(t, i)
			xs[i] = New(u, k)
		}
		fn(xs)
		for i := range xs {
			require.Nil(t, xs[i].Close())
		}
	})
}

func TestSuiteUDP(t *testing.T) {
	t.Parallel()
	swarmtest.TestSuiteSwarm(t, func(n int, fn func(xs []p2p.Swarm)) {
		xs := make([]p2p.Swarm, n)
		for i := range xs {
			u, err := udpswarm.New("127.0.0.1:")
			require.Nil(t, err)
			k := p2ptest.GetTestKey(t, i)
			xs[i] = New(u, k)
		}
		fn(xs)
		for i := range xs {
			require.Nil(t, xs[i].Close())
		}
	})
}
