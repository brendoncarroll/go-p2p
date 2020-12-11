package noiseswarm

import (
	"os"
	"testing"

	"github.com/brendoncarroll/go-p2p"
	"github.com/brendoncarroll/go-p2p/p2ptest"
	"github.com/brendoncarroll/go-p2p/s/memswarm"
	"github.com/brendoncarroll/go-p2p/s/swarmtest"
)

func TestSwarm(t *testing.T) {
	t.Parallel()
	swarmtest.TestSuiteSwarm(t, func(t testing.TB, n int) []p2p.Swarm {
		opts := []memswarm.Option{memswarm.WithLogging(os.Stderr)}
		r := memswarm.NewRealm(opts...)
		xs := make([]p2p.Swarm, n)
		for i := range xs {
			k := p2ptest.NewTestKey(t, i)
			xs[i] = New(r.NewSwarm(), k)
		}
		t.Cleanup(func() {
			swarmtest.CloseSwarms(t, xs)
		})
		return xs
	})
}
