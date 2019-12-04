package udpswarm

import (
	"context"
	"sync"
	"testing"

	"github.com/brendoncarroll/go-p2p"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestTell(t *testing.T) {
	ctx := context.TODO()
	s1, err := New("127.0.0.1:")
	require.Nil(t, err)
	s2, err := New("127.0.0.1:")
	require.Nil(t, err)

	wg := sync.WaitGroup{}
	wg.Add(1)
	recvMsg := p2p.Message{}
	s1.OnTell(func(msg *p2p.Message) {
		recvMsg = *msg
		wg.Done()
	})
	s2.Tell(ctx, s1.LocalAddr(), []byte("test123"))
	wg.Wait()

	expectedMsg := p2p.Message{
		Src:     s2.LocalAddr(),
		Dst:     s1.LocalAddr(),
		Payload: []byte("test123"),
	}
	assert.Equal(t, expectedMsg, recvMsg)
}
