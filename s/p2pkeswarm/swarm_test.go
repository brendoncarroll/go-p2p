package p2pkeswarm

import (
	"testing"

	"github.com/brendoncarroll/go-p2p"
	"github.com/brendoncarroll/go-p2p/p2ptest"
	"github.com/brendoncarroll/go-p2p/s/memswarm"
	"github.com/brendoncarroll/go-p2p/s/swarmtest"
)

func TestSwarm(t *testing.T) {
	swarmtest.TestSwarm(t, func(t testing.TB, xs []p2p.Swarm[Addr[memswarm.Addr]]) {
		r := memswarm.NewRealm()
		for i := range xs {
			pk := p2ptest.NewTestKey(t, i)
			sw := r.NewSwarmWithKey(pk)
			xs[i] = New[memswarm.Addr](sw, pk)
		}
	})
}
