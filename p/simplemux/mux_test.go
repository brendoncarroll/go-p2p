package simplemux

import (
	"bytes"
	"context"
	"testing"

	"github.com/brendoncarroll/go-p2p"
	"github.com/brendoncarroll/go-p2p/s/memswarm"
	"github.com/stretchr/testify/require"
	"gotest.tools/assert"
)

func TestMux(t *testing.T) {
	r := memswarm.NewRealm()
	s1 := r.NewSwarm()
	s2 := r.NewSwarm()

	m1 := MultiplexSwarm(s1)
	m2 := MultiplexSwarm(s2)

	m1foo, err := m1.Open("foo")
	require.Nil(t, err)
	m2foo, err := m2.Open("foo")
	require.Nil(t, err)
	m1bar, err := m1.Open("bar")
	require.Nil(t, err)
	m2bar, err := m2.Open("bar")

	var recvFoo, recvBar string
	m1foo.OnTell(func(msg *p2p.Message) {
		recvFoo = string(msg.Payload)
	})
	m1bar.OnTell(func(msg *p2p.Message) {
		recvBar = string(msg.Payload)
	})

	err = m2foo.Tell(context.TODO(), m1foo.LocalAddrs()[0], bytes.NewReader([]byte("hello foo")))
	require.Nil(t, err)
	err = m2bar.Tell(context.TODO(), m1bar.LocalAddrs()[0], bytes.NewReader([]byte("hello bar")))
	require.Nil(t, err)

	assert.Equal(t, "hello foo", recvFoo)
	assert.Equal(t, "hello bar", recvBar)
}
