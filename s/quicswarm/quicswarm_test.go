package quicswarm

import (
	"testing"

	"github.com/brendoncarroll/go-p2p"
	"github.com/brendoncarroll/go-p2p/p2ptest"
	"github.com/brendoncarroll/go-p2p/s/swarmtest"
	"github.com/stretchr/testify/require"
)

func TestQUICSwarm(t *testing.T) {
	t.Parallel()
	swarmtest.TestSuiteSwarm(t, func(t testing.TB, n int) []p2p.Swarm {
		xs := make([]p2p.Swarm, n)
		for i := range xs {
			privKey := p2ptest.NewTestKey(t, i)
			s, err := New("127.0.0.1:", privKey)
			require.Nil(t, err)
			xs[i] = s
		}
		t.Cleanup(func() { swarmtest.CloseSwarms(t, xs) })
		return xs
	})
	swarmtest.TestSuiteAskSwarm(t, func(t testing.TB, n int) []p2p.AskSwarm {
		xs := make([]p2p.AskSwarm, n)
		for i := range xs {
			privKey := p2ptest.NewTestKey(t, i)
			s, err := New("127.0.0.1:", privKey)
			require.Nil(t, err)
			xs[i] = s
		}
		t.Cleanup(func() { swarmtest.CloseAskSwarms(t, xs) })
		return xs
	})
	swarmtest.TestSuiteSecureSwarm(t, func(t testing.TB, n int) []p2p.SecureSwarm {
		xs := make([]p2p.SecureSwarm, n)
		for i := range xs {
			privKey := p2ptest.NewTestKey(t, i)
			s, err := New("127.0.0.1:", privKey)
			require.Nil(t, err)
			xs[i] = s
		}
		t.Cleanup(func() { swarmtest.CloseSecureSwarms(t, xs) })
		return xs
	})
}
