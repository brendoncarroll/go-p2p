package memswarm

import (
	"testing"

	"github.com/brendoncarroll/go-p2p"
	"github.com/brendoncarroll/go-p2p/s/swarmtest"
)

func TestSwarm(t *testing.T) {
	t.Parallel()
	swarmtest.TestSuiteSwarm(t, func(n int, fn func(xs []p2p.Swarm)) {
		xs := make([]p2p.Swarm, n)
		r := NewRealm()
		for i := range xs {
			xs[i] = r.NewSwarm()
		}
		fn(xs)
		swarmtest.CloseSwarms(t, xs)
	})
	swarmtest.TestSuiteAskSwarm(t, func(n int, fn func(xs []p2p.AskSwarm)) {
		xs := make([]p2p.AskSwarm, n)
		r := NewRealm()
		for i := range xs {
			xs[i] = r.NewSwarm()
		}
		fn(xs)
		for i := range xs {
			xs[i].Close()
		}
	})
}
