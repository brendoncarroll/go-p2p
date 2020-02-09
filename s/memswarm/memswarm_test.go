package memswarm

import (
	"testing"

	"github.com/brendoncarroll/go-p2p"
	"github.com/brendoncarroll/go-p2p/s/swarmutil"
)

func TestSwarm(t *testing.T) {
	swarmutil.TestSuite(t, func(xs []p2p.Swarm) {
		r := NewRealm()
		for i := range xs {
			xs[i] = r.NewSwarm()
		}
	})
}
