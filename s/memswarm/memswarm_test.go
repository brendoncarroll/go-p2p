package memswarm

import (
	"testing"

	"github.com/brendoncarroll/go-p2p"
	"github.com/brendoncarroll/go-p2p/s/swarmtest"
	"github.com/stretchr/testify/require"
)

func TestSwarm(t *testing.T) {
	t.Parallel()
	swarmtest.TestSuiteSwarm(t, func(t testing.TB, n int) []p2p.Swarm {
		xs := make([]p2p.Swarm, n)
		r := NewRealm()
		for i := range xs {
			xs[i] = r.NewSwarm()
		}
		t.Cleanup(func() {
			swarmtest.CloseSwarms(t, xs)
		})
		return xs
	})
	swarmtest.TestSuiteAskSwarm(t, func(t testing.TB, n int) []p2p.AskSwarm {
		xs := make([]p2p.AskSwarm, n)
		r := NewRealm()
		for i := range xs {
			xs[i] = r.NewSwarm()
		}
		t.Cleanup(func() {
			for i := range xs {
				require.Nil(t, xs[i].Close())
			}
		})
		return xs
	})
}
