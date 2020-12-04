package swarmtest

import (
	"testing"

	"github.com/brendoncarroll/go-p2p"
	"github.com/stretchr/testify/require"
)

func TestSuiteSecureSwarm(t *testing.T, newSwarms func(t testing.TB, n int) []p2p.SecureSwarm) {
	t.Run("TestNotNilPublicKey", func(t *testing.T) {
		x := newSwarms(t, 1)[0]
		require.NotNil(t, x.PublicKey())
	})
}
