package dynmux

import (
	"context"
	"testing"

	"github.com/brendoncarroll/go-p2p"
	"github.com/brendoncarroll/go-p2p/s/memswarm"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sync/errgroup"
)

func TestMux(t *testing.T) {
	r := memswarm.NewRealm()
	s1 := r.NewSwarm()
	s2 := r.NewSwarm()

	m1 := MultiplexSwarm(s1)
	m2 := MultiplexSwarm(s2)

	m1foo, err := m1.Open("foo")
	require.NoError(t, err)
	m2foo, err := m2.Open("foo")
	require.NoError(t, err)
	m1bar, err := m1.Open("bar")
	require.NoError(t, err)
	m2bar, err := m2.Open("bar")
	require.NoError(t, err)

	eg := errgroup.Group{}
	ctx := context.Background()
	var recvFoo, recvBar string
	eg.Go(func() error {
		var src, dst p2p.Addr
		buf := make([]byte, m1foo.MaxIncomingSize())
		n, err := m1foo.Recv(ctx, &src, &dst, buf)
		if err != nil {
			return err
		}
		recvFoo = string(buf[:n])
		return nil
	})
	eg.Go(func() error {
		var src, dst p2p.Addr
		buf := make([]byte, m1foo.MaxIncomingSize())
		n, err := m1bar.Recv(ctx, &src, &dst, buf)
		if err != nil {
			return err
		}
		recvBar = string(buf[:n])
		return nil
	})

	err = m2foo.Tell(context.TODO(), m1foo.LocalAddrs()[0], p2p.IOVec{[]byte("hello foo")})
	require.Nil(t, err)
	err = m2bar.Tell(context.TODO(), m1bar.LocalAddrs()[0], p2p.IOVec{[]byte("hello bar")})
	require.Nil(t, err)
	require.NoError(t, eg.Wait())

	assert.Equal(t, "hello foo", recvFoo)
	assert.Equal(t, "hello bar", recvBar)
}
