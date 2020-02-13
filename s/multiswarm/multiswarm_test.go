package multiswarm

import (
	"testing"

	"github.com/brendoncarroll/go-p2p"
	"github.com/brendoncarroll/go-p2p/p2ptest"
	"github.com/brendoncarroll/go-p2p/s/memswarm"
	"github.com/brendoncarroll/go-p2p/s/swarmutil"
)

func TestMultiSwarm(t *testing.T) {
	swarmutil.TestSuite(t, func(xs []p2p.Swarm) {
		r1 := memswarm.NewRealm()
		r2 := memswarm.NewRealm()

		for i := range xs {
			privKey := p2ptest.GetTestKey(t, i)
			m := map[string]p2p.SecureAskSwarm{
				"mem1": r1.NewSwarmWithKey(privKey),
				"mem2": r2.NewSwarmWithKey(privKey),
			}
			x := NewSecureAsk(m)
			xs[i] = x
		}
	})
}
