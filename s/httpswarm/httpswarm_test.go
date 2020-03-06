package httpswarm

import (
	"testing"

	"github.com/brendoncarroll/go-p2p"
	"github.com/brendoncarroll/go-p2p/s/swarmutil"
	"github.com/stretchr/testify/require"
)

func TestSuite(t *testing.T) {
	swarmutil.TestSuite(t, func(xs []p2p.Swarm) {
		for i := range xs {
			s, err := New("127.0.0.1:")
			require.Nil(t, err)
			xs[i] = s
		}
	})
}
