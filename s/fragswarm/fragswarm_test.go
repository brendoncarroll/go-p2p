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
	swarmtest.TestSwarm(t, func(t testing.TB, xs []p2p.Swarm) {
		r := memswarm.NewRealm()
		for i := range xs {
			xs[i] = New(r.NewSwarm(), 1<<16)
		}
		t.Cleanup(func() {
			swarmtest.CloseSwarms(t, xs)
		})
	})
}

func TestFragment(t *testing.T) {
	ctx := context.Background()
	r := memswarm.NewRealm(memswarm.WithMTU(100))
	const mtu = 1024
	a := New(r.NewSwarm(), mtu)
	b := New(r.NewSwarm(), mtu)

	buf := make([]byte, b.MaxIncomingSize())
	done := make(chan struct{})
	go func() error {
		defer close(done)
		var src, dst p2p.Addr
		n, err := b.Recv(ctx, &src, &dst, buf)
		if err != nil {
			return err
		}
		buf = buf[:n]
		return nil
	}()

	send := make([]byte, 1024)
	for i := range send {
		send[i] = 0xff
	}
	require.NoError(t, a.Tell(ctx, b.LocalAddrs()[0], p2p.IOVec{send}))
	<-done
	require.Equal(t, send, buf)
}
