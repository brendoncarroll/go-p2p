package noiseswarm

import (
	"os"
	"testing"

	"github.com/brendoncarroll/go-p2p"
	"github.com/brendoncarroll/go-p2p/p2ptest"
	"github.com/brendoncarroll/go-p2p/s/memswarm"
	"github.com/brendoncarroll/go-p2p/s/swarmtest"
)

func TestSwarm(t *testing.T) {
	t.Parallel()
	swarmtest.TestSuiteSwarm(t, func(t testing.TB, n int) []p2p.Swarm {
		opts := []memswarm.Option{}
		opts = append(opts, memswarm.WithLogging(os.Stderr))
		r := memswarm.NewRealm(opts...)
		xs := make([]p2p.Swarm, n)
		for i := range xs {
			k := p2ptest.NewTestKey(t, i+1)
			xs[i] = New(r.NewSwarm(), k)
		}
		t.Cleanup(func() {
			swarmtest.CloseSwarms(t, xs)
		})
		return xs
	})
}

// func TestNoise(t *testing.T) {
// 	cs := noise.NewCipherSuite(noise.DH25519, noise.CipherChaChaPoly, noise.HashBLAKE2b)
// 	staticI, _ := noise.DH25519.GenerateKeypair(nil)
// 	staticR, _ := noise.DH25519.GenerateKeypair(nil)
// 	hsI, _ := noise.NewHandshakeState(noise.Config{
// 		CipherSuite:   cs,
// 		Pattern:       noise.HandshakeXX,
// 		Initiator:     true,
// 		StaticKeypair: staticI,
// 	})
// 	hsR, _ := noise.NewHandshakeState(noise.Config{
// 		CipherSuite:   cs,
// 		Pattern:       noise.HandshakeXX,
// 		StaticKeypair: staticR,
// 	})
// 	assert := assert.New(t)
// 	msg, _, _, err := hsI.WriteMessage(nil, nil)
// 	assert.Len(msg, 32)
// 	assert.NoError(err)
// 	res, _, _, err := hsR.ReadMessage(nil, msg)
// 	assert.NoError(err)
// 	assert.Equal(string(res), "")

// 	msg, _, _, err = hsR.WriteMessage(nil, nil)
// 	assert.NoError(err)
// 	assert.Len(msg, 96)
// 	res, _, _, err = hsI.ReadMessage(nil, msg)
// 	assert.NoError(err)
// 	assert.Equal(string(res), "")

// 	msg, _, _, err = hsI.WriteMessage(nil, nil)
// 	assert.Len(msg, 64)
// 	assert.NoError(err)
// 	res, _, _, err = hsR.ReadMessage(nil, msg)
// 	assert.NoError(err)
// 	assert.Len(res, 0)
// 	//expected, _ := hex.DecodeString("8127f4b35cdbdf0935fcf1ec99016d1dcbc350055b8af360be196905dfb50a2c1c38a7ca9cb0cfe8f4576f36c47a4933eee32288f590ac4305d4b53187577be7")
// 	//assert.Equal(msg, expected)
// }
