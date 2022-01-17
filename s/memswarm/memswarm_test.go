package memswarm

import (
	"testing"

	"github.com/brendoncarroll/go-p2p"
	"github.com/brendoncarroll/go-p2p/s/swarmtest"
	"github.com/stretchr/testify/require"
)

func TestSwarm(t *testing.T) {
	t.Parallel()
	swarmtest.TestSwarm(t, func(t testing.TB, xs []p2p.Swarm[Addr]) {
		r := NewRealm()
		for i := range xs {
			xs[i] = r.NewSwarm()
		}
		t.Cleanup(func() {
			swarmtest.CloseSwarms(t, xs)
		})
	})
	swarmtest.TestAskSwarm(t, func(t testing.TB, xs []p2p.AskSwarm[Addr]) {
		r := NewRealm()
		for i := range xs {
			xs[i] = r.NewSwarm()
		}
		t.Cleanup(func() {
			for i := range xs {
				require.Nil(t, xs[i].Close())
			}
		})
	})
	swarmtest.TestSecureSwarm(t, func(t testing.TB, xs []p2p.SecureSwarm[Addr]) {
		r := NewRealm()
		for i := range xs {
			xs[i] = r.NewSwarm()
		}
		t.Cleanup(func() {
			for i := range xs {
				require.Nil(t, xs[i].Close())
			}
		})
	})
}
