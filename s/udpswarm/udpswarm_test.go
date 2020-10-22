package udpswarm

import (
	"testing"

	"github.com/brendoncarroll/go-p2p"
	"github.com/brendoncarroll/go-p2p/s/swarmtest"
	"github.com/stretchr/testify/require"
)

func TestSwarm(t *testing.T) {
	swarmtest.TestSuiteSwarm(t, func(n int, fn func(xs []p2p.Swarm)) {
		xs := make([]p2p.Swarm, n)
		for i := range xs {
			s, err := New("127.0.0.1:")
			require.Nil(t, err)
			xs[i] = s
		}
		fn(xs)
		swarmtest.CloseSwarms(t, xs)
	})
}
