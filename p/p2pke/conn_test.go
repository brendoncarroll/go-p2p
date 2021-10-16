package p2pke

import (
	"context"
	"testing"

	"github.com/brendoncarroll/go-p2p/p2ptest"
	"github.com/stretchr/testify/require"
)

func TestConn(t *testing.T) {
	ctx := context.Background()
	c1, c2 := newConnPair(t)
	var c1Out, c2Out []string
	var send1, send2 func([]byte)
	send1 = func(x []byte) {
		t.Logf("1->2: %q", x)
		out, err := c2.Deliver(ctx, nil, x, send2)
		require.NoError(t, err)
		if out != nil {
			c2Out = append(c2Out, string(out))
		}
	}
	send2 = func(x []byte) {
		t.Logf("2->1: %q", x)
		out, err := c1.Deliver(ctx, nil, x, send1)
		require.NoError(t, err)
		if out != nil {
			c1Out = append(c1Out, string(out))
		}
	}
	testData := "test data"
	c1.Send(ctx, []byte(testData), send1)
	require.Len(t, c2Out, 1)
	require.Equal(t, c2Out[0], testData)
	c2.Send(ctx, []byte(testData), send2)
	require.Len(t, c1Out, 1)
	require.Equal(t, c1Out[0], testData)

	require.Equal(t, c1.RemoteKey(), c2.LocalKey())
	require.Equal(t, c2.RemoteKey(), c1.LocalKey())
}

func newConnPair(t *testing.T) (c1, c2 *Conn) {
	c1 = NewConn(p2ptest.NewTestKey(t, 0), nil)
	c2 = NewConn(p2ptest.NewTestKey(t, 1), nil)
	return c1, c2
}
