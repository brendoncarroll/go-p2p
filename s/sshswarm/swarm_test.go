package sshswarm

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
			privKey := getPrivateKey(0)
			s, err := New("127.0.0.1:", privKey, nil)
			require.Nil(t, err)
			xs[i] = s
		}
	})
}

func getPrivateKey(i uint8) ed25519.PrivateKey {
	seed := make([]byte, ed25519.SeedSize)
	seed[0] = i
	return ed25519.NewKeyFromSeed(seed)
}
