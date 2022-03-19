package udpswarm

import (
	"testing"

	"github.com/brendoncarroll/go-p2p"
	"github.com/brendoncarroll/go-p2p/s/swarmtest"
	"github.com/stretchr/testify/require"
)

func TestSwarm(t *testing.T) {
	t.Parallel()
	swarmtest.TestSwarm(t, func(t testing.TB, xs []p2p.Swarm[Addr]) {
		for i := range xs {
			s, err := New("127.0.0.1:")
			require.Nil(t, err)
			xs[i] = s
		}
		t.Cleanup(func() {
			swarmtest.CloseSwarms(t, xs)
		})
	})
}
