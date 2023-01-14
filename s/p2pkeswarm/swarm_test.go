package p2pkeswarm

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/brendoncarroll/go-p2p"
	"github.com/brendoncarroll/go-p2p/f/x509"
	"github.com/brendoncarroll/go-p2p/p2ptest"
	"github.com/brendoncarroll/go-p2p/s/memswarm"
	"github.com/brendoncarroll/go-p2p/s/swarmtest"
	"github.com/brendoncarroll/go-p2p/s/udpswarm"
)

func testSwarm[T p2p.Addr](t *testing.T, baseSwarms func(testing.TB, []p2p.Swarm[T])) {
	swarmtest.TestSwarm(t, func(t testing.TB, xs []p2p.Swarm[Addr[T]]) {
		ss := make([]p2p.Swarm[T], len(xs))
		baseSwarms(t, ss)
		for i := range xs {
			privKey := newTestKey(t, i)
			s := New(ss[i], privKey)
			xs[i] = s
		}
		t.Cleanup(func() { swarmtest.CloseSwarms(t, xs) })
	})
	swarmtest.TestSecureSwarm(t, func(t testing.TB, xs []p2p.SecureSwarm[Addr[T], x509.PublicKey]) {
		ss := make([]p2p.Swarm[T], len(xs))
		baseSwarms(t, ss)
		for i := range xs {
			privKey := newTestKey(t, i)
			s := New(ss[i], privKey)
			xs[i] = s
		}
		t.Cleanup(func() { swarmtest.CloseSecureSwarms(t, xs) })
	})
}

func TestOnUDP(t *testing.T) {
	t.Parallel()
	testSwarm(t, func(t testing.TB, xs []p2p.Swarm[udpswarm.Addr]) {
		for i := range xs {
			var err error
			xs[i], err = udpswarm.New("127.0.0.1:")
			require.NoError(t, err)
		}
	})
}

func TestOnMem(t *testing.T) {
	t.Parallel()
	testSwarm(t, func(t testing.TB, xs []p2p.Swarm[memswarm.Addr]) {
		var opts []memswarm.Option[memswarm.Addr]
		// opts = append(opts, memswarm.WithLogging(os.Stdout))
		r := memswarm.NewRealm(opts...)
		for i := range xs {
			xs[i] = r.NewSwarm()
		}
	})
}

func TestOnDropFirstPairwise(t *testing.T) {
	t.Parallel()
	testSwarm(t, func(t testing.TB, xs []p2p.Swarm[memswarm.Addr]) {
		var opts []memswarm.Option[memswarm.Addr]
		opts = append(opts, memswarm.WithTellTransform[memswarm.Addr](p2ptest.NewDropFirstPairwise()))
		r := memswarm.NewRealm(opts...)
		for i := range xs {
			xs[i] = r.NewSwarm()
		}
	})
}

func newTestKey(t testing.TB, i int) x509.PrivateKey {
	pk := p2ptest.NewTestKey(t, i)
	algoID, signer := x509.SignerFromStandard(pk)
	reg := x509.DefaultRegistry()
	privateKey, err := reg.StoreSigner(algoID, signer)
	require.NoError(t, err)
	return privateKey
}
