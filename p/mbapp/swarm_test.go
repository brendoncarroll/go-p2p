package mbapp

import (
	"testing"

	"github.com/brendoncarroll/go-p2p"
	"github.com/brendoncarroll/go-p2p/s/memswarm"
	"github.com/brendoncarroll/go-p2p/s/swarmtest"
)

func init() {
	disableFastPath = true
}

func TestSwarm(t *testing.T) {
	swarmtest.TestSwarm(t, func(t testing.TB, xs []p2p.Swarm) {
		r := memswarm.NewRealm()
		for i := range xs {
			s := r.NewSwarm()
			xs[i] = New(s, 1<<20)
		}
	})
	swarmtest.TestAskSwarm(t, func(t testing.TB, xs []p2p.AskSwarm) {
		r := memswarm.NewRealm()
		for i := range xs {
			s := r.NewSwarm()
			xs[i] = New(s, 1<<20)
		}
	})
}
