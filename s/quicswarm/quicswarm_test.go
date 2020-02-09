package quicswarm

import (
	"crypto/ed25519"
	"testing"

	"github.com/brendoncarroll/go-p2p"
	"github.com/brendoncarroll/go-p2p/s/swarmutil"
	"github.com/stretchr/testify/require"
)

func TestSwarm(t *testing.T) {
	swarmutil.TestSuite(t, func(xs []p2p.Swarm) {
		for i := range xs {
			privKey := getPrivateKey(i)
			s, err := New("127.0.0.1:", privKey)
			require.Nil(t, err)
			xs[i] = s
		}
	})
}

func getPrivateKey(i int) p2p.PrivateKey {
	seed := make([]byte, ed25519.SeedSize)
	seed[0] = uint8(i)
	return ed25519.NewKeyFromSeed(seed)
}
