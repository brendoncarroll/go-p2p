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
	init := NewHandshakeState[XOFStateV1, KEMPrivateKeyV1, KEMPublicKeyV1](NewV1(), newSeed(t, 0), true)
	resp := NewHandshakeState[XOFStateV1, KEMPrivateKeyV1, KEMPublicKeyV1](NewV1(), newSeed(t, 1), false)
	require.Equal(t, init.ChannelBinding(), resp.ChannelBinding())

	transmit := func(send, recv *HandshakeState[XOFStateV1, KEMPrivateKeyV1, KEMPublicKeyV1]) {
		i := send.Index()
		var err error
		var buf []byte
		buf, err = send.Send(buf)
		require.NoError(t, err)
		err = recv.Deliver(buf)
		require.NoError(t, err)
		require.Equal(t, send.ChannelBinding(), recv.ChannelBinding(), "diverged handshakes after message", i)
	}
	for !init.IsDone() || !resp.IsDone() {
		if !init.IsDone() {
			transmit(&init, &resp)
		}
		if !resp.IsDone() {
			transmit(&resp, &init)
		}
	}
}

func newSeed(t testing.TB, i int) *[32]byte {
	var ret [32]byte
	ret[i] = uint8(i)
	return &ret
}
