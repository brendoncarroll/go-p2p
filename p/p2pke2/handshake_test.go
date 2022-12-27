package p2pke2

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestSchemeV1(t *testing.T) {
	sch := NewV1()
	t.Log(sch.Name)
}

func TestHandshake(t *testing.T) {
	init := NewHandshakeState[XOFV1, KEMPrivateKeyV1, KEMPublicKeyV1](NewV1(), newSeed(0), true)
	resp := NewHandshakeState[XOFV1, KEMPrivateKeyV1, KEMPublicKeyV1](NewV1(), newSeed(1), false)
	require.Equal(t, init.ChannelBinding(), resp.ChannelBinding())

	for !init.IsDone() || !resp.IsDone() {
		var err error
		if !init.IsDone() {
			var buf []byte
			buf, err = init.Send(buf)
			require.NoError(t, err)
			err = resp.Deliver()
			require.NoError(t, err)
		}
		if !resp.IsDone() {
			var buf []byte
			buf, err = resp.Send(buf)
			require.NoError(t, err)
			err = init.Deliver(buf)
			require.NoError(t, err)
		}
		require.Equal(t, init.ChannelBinding(), resp.ChannelBinding())
	}
}

func newSeed(t testing.TB, i int) (ret [32]byte) {
	ret[i] = uint8(i)
	return ret
}
