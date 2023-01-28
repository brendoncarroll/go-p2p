package quicswarm

import (
	"testing"

	"github.com/brendoncarroll/go-p2p"
	"github.com/brendoncarroll/go-p2p/crypto/sign/sig_ed25519"
	"github.com/brendoncarroll/go-p2p/f/x509"
	"github.com/brendoncarroll/go-p2p/p2ptest"
	"github.com/brendoncarroll/go-p2p/s/memswarm"
	"github.com/brendoncarroll/go-p2p/s/swarmtest"
	"github.com/brendoncarroll/go-p2p/s/udpswarm"
	"github.com/stretchr/testify/require"
)

func testSwarm[T p2p.Addr](t *testing.T, baseSwarms func(testing.TB, []p2p.Swarm[T])) {
	swarmtest.TestSwarm(t, func(t testing.TB, xs []p2p.Swarm[Addr[T]]) {
		ss := make([]p2p.Swarm[T], len(xs))
		baseSwarms(t, ss)
		for i := range xs {
			privKey := newTestKey(t, i)
			s, err := New(ss[i], privKey)
			require.NoError(t, err)
			xs[i] = s
		}
		t.Cleanup(func() { swarmtest.CloseSwarms(t, xs) })
	})
	swarmtest.TestAskSwarm(t, func(t testing.TB, xs []p2p.AskSwarm[Addr[T]]) {
		ss := make([]p2p.Swarm[T], len(xs))
		baseSwarms(t, ss)
		for i := range xs {
			privKey := newTestKey(t, i)
			s, err := New(ss[i], privKey)
			require.NoError(t, err)
			xs[i] = s
		}
		t.Cleanup(func() { swarmtest.CloseAskSwarms(t, xs) })
	})
	swarmtest.TestSecureSwarm(t, func(t testing.TB, xs []p2p.SecureSwarm[Addr[T], x509.PublicKey]) {
		ss := make([]p2p.Swarm[T], len(xs))
		baseSwarms(t, ss)
		for i := range xs {
			privKey := newTestKey(t, i)
			s, err := New(ss[i], privKey)
			require.NoError(t, err)
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
		opts := []memswarm.Option{memswarm.WithQueueLen(10)}
		// opts = append(opts, memswarm.WithLogging(os.Stdout))
		r := memswarm.NewRealm(opts...)
		for i := range xs {
			xs[i] = r.NewSwarm()
		}
	})
}

func newTestKey(t testing.TB, i int) x509.PrivateKey {
	k := p2ptest.NewTestKey(t, i)
	sch := sig_ed25519.New()
	data := make([]byte, sch.PrivateKeySize())
	priv := sig_ed25519.PrivateKeyFromStandard(k)
	sch.MarshalPrivate(data, &priv)
	return x509.PrivateKey{
		Algorithm: x509.Algo_Ed25519,
		Data:      data,
	}
}
