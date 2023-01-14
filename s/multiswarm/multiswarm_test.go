package multiswarm

import (
	"strconv"
	"testing"

	"github.com/brendoncarroll/go-p2p"
	"github.com/brendoncarroll/go-p2p/s/memswarm"
	"github.com/brendoncarroll/go-p2p/s/swarmtest"
)

func TestMultiSwarm(t *testing.T) {
	t.Parallel()
	swarmtest.TestSwarm(t, func(t testing.TB, xs []p2p.Swarm[Addr]) {
		r1 := memswarm.NewRealm[string]()
		r2 := memswarm.NewRealm[string]()

		for i := range xs {
			pubKey := strconv.Itoa(i)
			m := map[string]DynSecureAskSwarm[string]{
				"mem1": WrapSecureAskSwarm[memswarm.Addr, string](r1.NewSwarmWithKey(pubKey)),
				"mem2": WrapSecureAskSwarm[memswarm.Addr, string](r2.NewSwarmWithKey(pubKey)),
			}
			x := NewSecureAsk(m)
			xs[i] = x
		}
		t.Cleanup(func() {
			swarmtest.CloseSwarms(t, xs)
		})
	})
	swarmtest.TestAskSwarm(t, func(t testing.TB, xs []p2p.AskSwarm[Addr]) {
		r1 := memswarm.NewRealm[string]()
		r2 := memswarm.NewRealm[string]()

		for i := range xs {
			pubKey := strconv.Itoa(i)
			m := map[string]DynSecureAskSwarm[string]{
				"mem1": WrapSecureAskSwarm[memswarm.Addr, string](r1.NewSwarmWithKey(pubKey)),
				"mem2": WrapSecureAskSwarm[memswarm.Addr, string](r2.NewSwarmWithKey(pubKey)),
			}
			x := NewSecureAsk(m)
			xs[i] = x
		}
		t.Cleanup(func() {
			swarmtest.CloseAskSwarms(t, xs)
		})
	})
}
