package fragswarm

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
	swarmtest.TestSwarm(t, func(t testing.TB, xs []p2p.Swarm[memswarm.Addr]) {
		r := memswarm.NewRealm[struct{}]()
		for i := range xs {
			xs[i] = New[memswarm.Addr](r.NewSwarm(), 1<<16)
		}
		t.Cleanup(func() {
			swarmtest.CloseSwarms(t, xs)
		})
	})
}

func TestFragment(t *testing.T) {
	ctx := context.Background()
	r := memswarm.NewRealm[struct{}](memswarm.WithMTU[struct{}](100))
	const mtu = 1024
	a := New[memswarm.Addr](r.NewSwarm(), mtu)
	b := New[memswarm.Addr](r.NewSwarm(), mtu)

	var recv p2p.Message[memswarm.Addr]
	done := make(chan struct{})
	go func() error {
		defer close(done)
		if err := p2p.Receive[memswarm.Addr](ctx, b, &recv); err != nil {
			return err
		}
		return nil
	}()

	send := make([]byte, 1024)
	for i := range send {
		send[i] = 0xff
	}
	require.NoError(t, a.Tell(ctx, b.LocalAddrs()[0], p2p.IOVec{send}))
	<-done
	require.Equal(t, send, recv.Payload)
}
