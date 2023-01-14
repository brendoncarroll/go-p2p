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
	swarmtest.TestSwarm(t, func(t testing.TB, xs []p2p.Swarm[memswarm.Addr]) {
		r := memswarm.NewRealm[struct{}](memswarm.WithMTU[struct{}](1 << 16))
		for i := range xs {
			s := r.NewSwarm()
			xs[i] = New[memswarm.Addr, struct{}](s, 1<<20)
		}
	})
	swarmtest.TestAskSwarm(t, func(t testing.TB, xs []p2p.AskSwarm[memswarm.Addr]) {
		r := memswarm.NewRealm[struct{}](memswarm.WithMTU[struct{}](1 << 16))
		for i := range xs {
			s := r.NewSwarm()
			xs[i] = New[memswarm.Addr, struct{}](s, 1<<20)
		}
	})
}
