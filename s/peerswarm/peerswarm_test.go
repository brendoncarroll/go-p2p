package peerswarm

import (
	"testing"

	"github.com/brendoncarroll/go-p2p"
	"github.com/brendoncarroll/go-p2p/p2ptest"
	"github.com/brendoncarroll/go-p2p/s/memswarm"
	"github.com/brendoncarroll/go-p2p/s/swarmtest"
)

func TestPeerSwarm(t *testing.T) {
	t.Parallel()
	swarmtest.TestSuiteSwarm(t, func(t testing.TB, n int) []p2p.Swarm {
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
		t.Cleanup(func() {
			swarmtest.CloseSwarms(t, xs)
		})
		return xs
	})
}

func TestPeerAskSwarm(t *testing.T) {
	t.Parallel()
	swarmtest.TestSuiteAskSwarm(t, func(t testing.TB, n int) []p2p.AskSwarm {
		r := memswarm.NewRealm()
		//r = r.WithLogging(os.Stderr)
		addrMap := map[p2p.PeerID][]p2p.Addr{}
		xs := make([]p2p.AskSwarm, n)
		for i := range xs {
			u := r.NewSwarm()
			k := p2ptest.GetTestKey(t, i)
			addrMap[p2p.NewPeerID(k.Public())] = u.LocalAddrs()

			xs[i] = NewAskSwarm(u, func(id p2p.PeerID) []p2p.Addr {
				return addrMap[id]
			})
		}
		t.Cleanup(func() {
			swarmtest.CloseAskSwarms(t, xs)
		})
		return xs
	})
}
