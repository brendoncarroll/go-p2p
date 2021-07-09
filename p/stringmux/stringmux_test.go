package stringmux

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

	m1 := WrapSwarm(s1)
	m2 := WrapSwarm(s2)

	m1foo := m1.Open("foo-channel")
	m2foo := m2.Open("foo-channel")
	m1bar := m1.Open("bar-channel")
	m2bar := m2.Open("bar-channel")

	ctx := context.Background()
	var recvFoo, recvBar string
	eg := errgroup.Group{}
	eg.Go(func() error {
		buf := make([]byte, m1foo.MaxIncomingSize())
		var src, dst p2p.Addr
		n, err := m1foo.Recv(ctx, &src, &dst, buf)
		if err != nil {
			return err
		}
		recvFoo = string(buf[:n])
		return nil
	})
	eg.Go(func() error {
		buf := make([]byte, m1bar.MaxIncomingSize())
		var src, dst p2p.Addr
		n, err := m1bar.Recv(ctx, &src, &dst, buf)
		if err != nil {
			return err
		}
		recvBar = string(buf[:n])
		return nil
	})

	var err error
	err = m2foo.Tell(context.TODO(), m1foo.LocalAddrs()[0], p2p.IOVec{[]byte("hello foo")})
	require.Nil(t, err)
	err = m2bar.Tell(context.TODO(), m1bar.LocalAddrs()[0], p2p.IOVec{[]byte("hello bar")})
	require.Nil(t, err)

	require.NoError(t, eg.Wait())
	assert.Equal(t, "hello foo", recvFoo)
	assert.Equal(t, "hello bar", recvBar)
}
