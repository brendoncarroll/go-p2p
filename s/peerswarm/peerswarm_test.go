package peerswarm

import (
	"testing"

	"github.com/brendoncarroll/go-p2p"
	"github.com/brendoncarroll/go-p2p/p2ptest"
	"github.com/brendoncarroll/go-p2p/s/memswarm"
	"github.com/brendoncarroll/go-p2p/s/swarmtest"
)

func TestSuite(t *testing.T) {
	t.Parallel()
	swarmtest.TestSuiteSwarm(t, func(n int, fn func(xs []p2p.Swarm)) {
		r := memswarm.NewRealm()
		//r = r.WithLogging(os.Stderr)
		addrMap := map[p2p.PeerID][]p2p.Addr{}
		xs := make([]p2p.Swarm, n)
		for i := range xs {
			u := r.NewSwarm()
			k := p2ptest.GetTestKey(t, i)
			addrMap[p2p.NewPeerID(k.Public())] = u.LocalAddrs()

			xs[i] = NewSwarm(u, func(id p2p.PeerID) []p2p.Addr {
				return addrMap[id]
			})
		}
		fn(xs)
		swarmtest.CloseSwarms(t, xs)
	})
}
