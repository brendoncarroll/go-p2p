package p2pke2

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestSchemeV1(t *testing.T) {
	sch := NewV1(nil, nil)
	t.Log(sch.Name)
}

func TestHandshake(t *testing.T) {
	scheme := NewV1(func(out []byte, target *[64]byte) []byte {
		return out
	}, func(target *[64]byte, proof []byte) bool {
		return true
	})
	init := NewHandshakeState[XOFStateV1, KEMPrivateKeyV1, KEMPublicKeyV1](scheme, newSeed(t, 0), true)
	resp := NewHandshakeState[XOFStateV1, KEMPrivateKeyV1, KEMPublicKeyV1](scheme, newSeed(t, 1), false)
	require.Equal(t, init.ChannelBinding(), resp.ChannelBinding())

	transmit := func(send, recv *HandshakeState[XOFStateV1, KEMPrivateKeyV1, KEMPublicKeyV1]) {
		i := send.Index()
		buf, err := send.Send(nil)
		require.NoError(t, err, "sending message %d", i)
		err = recv.Deliver(buf)
		require.NoError(t, err, "delivering message %d", i)
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
	initIn, initOut := init.Split()
	respIn, respOut := resp.Split()
	require.Equal(t, initIn, respOut)
	require.Equal(t, respIn, initOut)
}

func newSeed(t testing.TB, i int) *[32]byte {
	var ret [32]byte
	ret[i] = uint8(i)
	return &ret
}
