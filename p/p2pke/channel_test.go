package p2pke

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/sync/errgroup"

	"go.brendoncarroll.net/p2p"
	"go.brendoncarroll.net/p2p/f/x509"
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
	c1.Send(ctx, p2p.IOVec{[]byte(testData)})
	require.Len(t, c2Out, 1)
	require.Equal(t, c2Out[0], testData)
	c2.Send(ctx, p2p.IOVec{[]byte(testData)})
	require.Len(t, c1Out, 1)
	require.Equal(t, c1Out[0], testData)

	require.Equal(t, c2.LocalKey(), c1.RemoteKey())
	require.Equal(t, c1.LocalKey(), c2.RemoteKey())
}

func TestChannelBidi(t *testing.T) {
	ctx := context.Background()
	var c1Out, c2Out []string
	c1, c2 := newChannelPair(t, func(x []byte) {
		c1Out = append(c1Out, string(x))
	}, func(x []byte) {
		c2Out = append(c2Out, string(x))
	})
	testData := "test data"
	eg := errgroup.Group{}
	eg.Go(func() error {
		return c1.Send(ctx, p2p.IOVec{[]byte(testData)})
	})
	eg.Go(func() error {
		return c2.Send(ctx, p2p.IOVec{[]byte(testData)})
	})
	require.NoError(t, eg.Wait())
}

func newChannelPair(t testing.TB, fn1, fn2 func([]byte)) (c1, c2 *Channel) {
	reg := x509.DefaultRegistry()
	c1 = NewChannel(ChannelConfig{
		Registry:   reg,
		PrivateKey: newTestKey(t, 0),
		Send: func(x []byte) {
			t.Logf("1->2: %q", x)
			out, err := c2.Deliver(nil, x)
			require.NoError(t, err)
			if out != nil {
				fn2(out)
			}
		},
		AcceptKey: func(*x509.PublicKey) bool { return true },
		Logger:    newTestLogger(t),
	})
	c2 = NewChannel(ChannelConfig{
		Registry:   reg,
		PrivateKey: newTestKey(t, 1),
		Send: func(x []byte) {
			t.Logf("2->1: %q", x)
			out, err := c1.Deliver(nil, x)
			require.NoError(t, err)
			if out != nil {
				fn1(out)
			}
		},
		AcceptKey: func(*x509.PublicKey) bool { return true },
		Logger:    newTestLogger(t),
	})
	t.Cleanup(func() {
		require.NoError(t, c1.Close())
		require.NoError(t, c2.Close())
	})
	return c1, c2
}
