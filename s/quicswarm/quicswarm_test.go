package quicswarm

import (
	"crypto/ed25519"
	"testing"

	"github.com/brendoncarroll/go-p2p"
	"github.com/brendoncarroll/go-p2p/s/swarmtest"
	"github.com/stretchr/testify/require"
)

func TestQUICSwarm(t *testing.T) {
	t.Parallel()
	swarmtest.TestSuiteSwarm(t, func(t testing.TB, n int) []p2p.Swarm {
		xs := make([]p2p.Swarm, n)
		for i := range xs {
			privKey := getPrivateKey(i)
			s, err := New("127.0.0.1:", privKey)
			require.Nil(t, err)
			xs[i] = s
		}
		t.Cleanup(func() {
			swarmtest.CloseSwarms(t, xs)
		})
		return xs
	})
	swarmtest.TestSuiteAskSwarm(t, func(t testing.TB, n int) []p2p.AskSwarm {
		xs := make([]p2p.AskSwarm, n)
		for i := range xs {
			privKey := getPrivateKey(i)
			s, err := New("127.0.0.1:", privKey)
			require.Nil(t, err)
			xs[i] = s
		}
		t.Cleanup(func() {
			swarmtest.CloseAskSwarms(t, xs)
		})
		return xs
	})
}

func getPrivateKey(i int) p2p.PrivateKey {
	seed := make([]byte, ed25519.SeedSize)
	seed[0] = uint8(i)
	return ed25519.NewKeyFromSeed(seed)
}
