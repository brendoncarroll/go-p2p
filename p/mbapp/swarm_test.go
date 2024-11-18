package mbapp

import (
	"testing"

	"go.brendoncarroll.net/p2p"
	"go.brendoncarroll.net/p2p/s/memswarm"
	"go.brendoncarroll.net/p2p/s/swarmtest"
)

func init() {
	disableFastPath = true
}

func TestSwarm(t *testing.T) {
	const underMTU = 1 << 16
	const aboveMTU = 1 << 20
	const queueLen = (aboveMTU / underMTU) + 1
	swarmtest.TestSwarm(t, func(t testing.TB, xs []p2p.Swarm[memswarm.Addr]) {
		r := memswarm.NewSecureRealm[struct{}](memswarm.WithMTU(1<<16), memswarm.WithQueueLen(queueLen))
		for i := range xs {
			s := r.NewSwarm(struct{}{})
			xs[i] = New[memswarm.Addr, struct{}](s, 1<<20)
		}
	})
	swarmtest.TestAskSwarm(t, func(t testing.TB, xs []p2p.AskSwarm[memswarm.Addr]) {
		r := memswarm.NewSecureRealm[struct{}](memswarm.WithMTU(1 << 16))
		for i := range xs {
			s := r.NewSwarm(struct{}{})
			xs[i] = New[memswarm.Addr, struct{}](s, 1<<20)
		}
	})
}
