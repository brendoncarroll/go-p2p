package p2pke

import (
	"context"
	"testing"

	"github.com/brendoncarroll/go-p2p/p2ptest"
	"github.com/stretchr/testify/require"
)

func TestChannel(t *testing.T) {
	ctx := context.Background()
	var c1Out, c2Out []string
	c1, c2 := newChannelPair(t, func(x []byte) {
		c1Out = append(c1Out, string(x))
	}, func(x []byte) {
		c2Out = append(c2Out, string(x))
	})
	testData := "test data"
	c1.Send(ctx, []byte(testData))
	require.Len(t, c2Out, 1)
	require.Equal(t, c2Out[0], testData)
	c2.Send(ctx, []byte(testData))
	require.Len(t, c1Out, 1)
	require.Equal(t, c1Out[0], testData)

	require.Equal(t, c1.RemoteKey(), c2.LocalKey())
	require.Equal(t, c2.RemoteKey(), c1.LocalKey())
}

func newChannelPair(t testing.TB, fn1, fn2 func([]byte)) (c1, c2 *Channel) {
	ctx := context.Background()
	c1 = NewChannel(p2ptest.NewTestKey(t, 0), nil, func(x []byte) {
		t.Logf("1->2: %q", x)
		out, err := c2.Deliver(ctx, nil, x)
		require.NoError(t, err)
		if out != nil {
			fn2(out)
		}
	})
	c2 = NewChannel(p2ptest.NewTestKey(t, 1), nil, func(x []byte) {
		t.Logf("2->1: %q", x)
		out, err := c1.Deliver(ctx, nil, x)
		require.NoError(t, err)
		if out != nil {
			fn1(out)
		}
	})
	t.Cleanup(func() {
		require.NoError(t, c1.Close())
		require.NoError(t, c2.Close())
	})
	return c1, c2
}
