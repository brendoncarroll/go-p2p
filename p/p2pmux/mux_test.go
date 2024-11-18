package p2pmux

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.brendoncarroll.net/p2p"
	"go.brendoncarroll.net/p2p/s/memswarm"
	"golang.org/x/sync/errgroup"
)

func TestStringMux(t *testing.T) {
	r := memswarm.NewRealm(memswarm.WithQueueLen(10))
	s1 := r.NewSwarm()
	s2 := r.NewSwarm()

	m1 := NewStringMux[memswarm.Addr](s1)
	m2 := NewStringMux[memswarm.Addr](s2)

	m1foo := m1.Open("foo-channel")
	m2foo := m2.Open("foo-channel")
	m1bar := m1.Open("bar-channel")
	m2bar := m2.Open("bar-channel")

	ctx := context.Background()
	var recvFoo, recvBar string
	eg := errgroup.Group{}
	eg.Go(func() error {
		var msg p2p.Message[memswarm.Addr]
		if err := p2p.Receive[memswarm.Addr](ctx, m1foo, &msg); err != nil {
			return err
		}
		recvFoo = string(msg.Payload)
		return nil
	})
	eg.Go(func() error {
		var msg p2p.Message[memswarm.Addr]
		if err := p2p.Receive[memswarm.Addr](ctx, m1bar, &msg); err != nil {
			return err
		}
		recvBar = string(msg.Payload)
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

func TestVarintMux(t *testing.T) {
	r := memswarm.NewRealm(memswarm.WithQueueLen(10))
	s1 := r.NewSwarm()
	s2 := r.NewSwarm()

	m1 := NewVarintMux[memswarm.Addr](s1)
	m2 := NewVarintMux[memswarm.Addr](s2)

	m1foo := m1.Open(0)
	m2foo := m2.Open(0)
	m1bar := m1.Open(20)
	m2bar := m2.Open(20)

	ctx := context.Background()
	var recvFoo, recvBar string
	eg := errgroup.Group{}
	eg.Go(func() error {
		var msg p2p.Message[memswarm.Addr]
		if err := p2p.Receive[memswarm.Addr](ctx, m1foo, &msg); err != nil {
			return err
		}
		recvFoo = string(msg.Payload)
		return nil
	})
	eg.Go(func() error {
		var msg p2p.Message[memswarm.Addr]
		if err := p2p.Receive[memswarm.Addr](ctx, m1bar, &msg); err != nil {
			return err
		}
		recvBar = string(msg.Payload)
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
