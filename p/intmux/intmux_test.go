package intmux

import (
	"context"
	"testing"

	"github.com/brendoncarroll/go-p2p"
	"github.com/brendoncarroll/go-p2p/s/memswarm"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMux(t *testing.T) {
	r := memswarm.NewRealm()
	s1 := r.NewSwarm()
	s2 := r.NewSwarm()

	m1 := WrapSwarm(s1)
	m2 := WrapSwarm(s2)

	m1foo := m1.Open(0)
	m2foo := m2.Open(0)
	m1bar := m1.Open(20)
	m2bar := m2.Open(20)

	var recvFoo, recvBar string
	go m1foo.ServeTells(func(msg *p2p.Message) {
		recvFoo = string(msg.Payload)
	})
	go m1bar.ServeTells(func(msg *p2p.Message) {
		recvBar = string(msg.Payload)
	})

	var err error
	err = m2foo.Tell(context.TODO(), m1foo.LocalAddrs()[0], p2p.IOVec{[]byte("hello foo")})
	require.Nil(t, err)
	err = m2bar.Tell(context.TODO(), m1bar.LocalAddrs()[0], p2p.IOVec{[]byte("hello bar")})
	require.Nil(t, err)

	assert.Equal(t, "hello foo", recvFoo)
	assert.Equal(t, "hello bar", recvBar)
}
