package swarmtest

import (
	"testing"

	"github.com/stretchr/testify/require"
	"go.brendoncarroll.net/p2p"
)

func TestSecureSwarm[A p2p.Addr, Pub any](t *testing.T, newSwarms func(testing.TB, []p2p.SecureSwarm[A, Pub])) {
	t.Run("TestNotNilPublicKey", func(t *testing.T) {
		xs := make([]p2p.SecureSwarm[A, Pub], 1)
		newSwarms(t, xs)
		x := xs[0]
		require.NotNil(t, x.PublicKey())
	})
}
