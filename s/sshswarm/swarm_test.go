package sshswarm

import (
	"testing"

	"github.com/brendoncarroll/go-p2p"
	"github.com/brendoncarroll/go-p2p/p2ptest"
	"github.com/brendoncarroll/go-p2p/s/swarmtest"
	"github.com/stretchr/testify/require"
)

func TestSwarm(t *testing.T) {
	t.Parallel()
	swarmtest.TestSwarm(t, func(t testing.TB, xs []p2p.Swarm[Addr]) {
		for i := range xs {
			privKey := p2ptest.NewTestKey(t, i)
			s, err := New("127.0.0.1:", privKey)
			require.Nil(t, err)
			xs[i] = s
		}
		t.Cleanup(func() {
			swarmtest.CloseSwarms(t, xs)
		})
	})
	swarmtest.TestAskSwarm(t, func(t testing.TB, xs []p2p.AskSwarm[Addr]) {
		for i := range xs {
			privKey := p2ptest.NewTestKey(t, i)
			s, err := New("127.0.0.1:", privKey)
			require.Nil(t, err)
			xs[i] = s
		}
		t.Cleanup(func() {
			swarmtest.CloseAskSwarms(t, xs)
		})
	})
	swarmtest.TestSecureSwarm(t, func(t testing.TB, xs []p2p.SecureSwarm[Addr]) {
		for i := range xs {
			privKey := p2ptest.NewTestKey(t, i)
			s, err := New("127.0.0.1:", privKey)
			require.Nil(t, err)
			xs[i] = s
		}
		t.Cleanup(func() {
			swarmtest.CloseSecureSwarms(t, xs)
		})
	})
}
