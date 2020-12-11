package aggswarm

import (
	"context"
	"testing"

	"github.com/brendoncarroll/go-p2p"
	"github.com/brendoncarroll/go-p2p/s/memswarm"
	"github.com/brendoncarroll/go-p2p/s/swarmtest"
	"github.com/stretchr/testify/require"
)

func TestSwarm(t *testing.T) {
	t.Parallel()
	swarmtest.TestSuiteSwarm(t, func(t testing.TB, n int) []p2p.Swarm {
		r := memswarm.NewRealm()
		xs := make([]p2p.Swarm, n)
		for i := range xs {
			xs[i] = New(r.NewSwarm(), 1<<16)
		}
		t.Cleanup(func() {
			swarmtest.CloseSwarms(t, xs)
		})
		return xs
	})
}

func TestAgg(t *testing.T) {
	ctx := context.Background()
	r := memswarm.NewRealm(memswarm.WithMTU(100))
	const mtu = 1024
	a := New(r.NewSwarm(), mtu)
	b := New(r.NewSwarm(), mtu)

	var recv []byte
	done := make(chan struct{})
	b.OnTell(func(m *p2p.Message) {
		recv = append([]byte{}, m.Payload...)
		close(done)
	})

	send := make([]byte, 1024)
	for i := range send {
		send[i] = 0xff
	}
	require.NoError(t, a.Tell(ctx, b.LocalAddrs()[0], send))
	<-done
	require.Equal(t, send, recv)
}
