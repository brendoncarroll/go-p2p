package dtlsswarm

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/brendoncarroll/go-p2p"
	"github.com/brendoncarroll/go-p2p/s/memswarm"
	"github.com/brendoncarroll/go-p2p/s/swarmtest"
	"github.com/brendoncarroll/go-p2p/s/udpswarm"
)

func TestSuiteMem(t *testing.T) {
	t.Parallel()
	swarmtest.TestSuiteSwarm(t, func(t testing.TB, n int) []p2p.Swarm {
		r := memswarm.NewRealm()
		//r = r.WithLogging(os.Stderr)
		xs := make([]p2p.Swarm, n)
		for i := range xs {
			u := r.NewSwarm()
			k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			if err != nil {
				panic(err)
			}
			//k := p2ptest.GetTestKey(t, i)
			xs[i] = New(u, k)
		}
		t.Cleanup(func() {
			for i := range xs {
				require.Nil(t, xs[i].Close())
			}
		})
		return xs
	})
}

func TestSuiteUDP(t *testing.T) {
	t.Parallel()
	swarmtest.TestSuiteSwarm(t, func(t testing.TB, n int) []p2p.Swarm {
		xs := make([]p2p.Swarm, n)
		for i := range xs {
			u, err := udpswarm.New("127.0.0.1:")
			require.Nil(t, err)
			k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			if err != nil {
				panic(err)
			}
			//k := p2ptest.GetTestKey(t, i)
			xs[i] = New(u, k)
		}
		t.Cleanup(func() {
			for i := range xs {
				require.Nil(t, xs[i].Close())
			}
		})
		return xs
	})
}
