package dtlsswarm

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/brendoncarroll/go-p2p"
	"github.com/brendoncarroll/go-p2p/p2ptest"
	"github.com/brendoncarroll/go-p2p/s/memswarm"
	"github.com/brendoncarroll/go-p2p/s/swarmutil"
	"github.com/brendoncarroll/go-p2p/s/udpswarm"
)

func TestSuite(t *testing.T) {
	swarmutil.TestSuite(t, func(xs []p2p.Swarm) {
		r := memswarm.NewRealm()
		//r = r.WithLogging(os.Stderr)
		for i := range xs {
			u := r.NewSwarm()
			k := p2ptest.GetTestKey(t, i)
			xs[i] = New(u, k)
		}
	})
}

func TestSuiteUDP(t *testing.T) {
	swarmutil.TestSuite(t, func(xs []p2p.Swarm) {
		for i := range xs {
			u, err := udpswarm.New("127.0.0.1:")
			require.Nil(t, err)
			k := p2ptest.GetTestKey(t, i)
			xs[i] = New(u, k)
		}
	})
}
