package quicswarm

import (
	"crypto/ed25519"
	"testing"

	"github.com/brendoncarroll/go-p2p"
	"github.com/brendoncarroll/go-p2p/s/swarmtest"
	"github.com/stretchr/testify/require"
)

func TestQUICSwarm(t *testing.T) {
	swarmtest.TestSuiteSwarm(t, func(n int, fn func(xs []p2p.Swarm)) {
		xs := make([]p2p.Swarm, n)
		for i := range xs {
			privKey := getPrivateKey(i)
			s, err := New("127.0.0.1:", privKey)
			require.Nil(t, err)
			xs[i] = s
		}
		fn(xs)
		swarmtest.CloseSwarms(t, xs)
	})
	swarmtest.TestSuiteAskSwarm(t, func(n int, fn func(xs []p2p.AskSwarm)) {
		xs := make([]p2p.AskSwarm, n)
		for i := range xs {
			privKey := getPrivateKey(i)
			s, err := New("127.0.0.1:", privKey)
			require.Nil(t, err)
			xs[i] = s
		}
		fn(xs)
		swarmtest.CloseAskSwarms(t, xs)
	})
}

func getPrivateKey(i int) p2p.PrivateKey {
	seed := make([]byte, ed25519.SeedSize)
	seed[0] = uint8(i)
	return ed25519.NewKeyFromSeed(seed)
}
