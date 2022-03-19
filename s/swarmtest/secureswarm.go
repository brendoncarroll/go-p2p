package swarmtest

import (
	"testing"

	"github.com/brendoncarroll/go-p2p"
	"github.com/stretchr/testify/require"
)

func TestSecureSwarm[A p2p.Addr](t *testing.T, newSwarms func(testing.TB, []p2p.SecureSwarm[A])) {
	t.Run("TestNotNilPublicKey", func(t *testing.T) {
		xs := make([]p2p.SecureSwarm[A], 1)
		newSwarms(t, xs)
		x := xs[0]
		require.NotNil(t, x.PublicKey())
	})
}
