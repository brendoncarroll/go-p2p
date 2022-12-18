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
	init := NewHandshakeState[XOFV1, KEMPrivateKeyV1, KEMPublicKeyV1](NewV1(), new([32]byte), true)
	resp := NewHandshakeState[XOFV1, KEMPrivateKeyV1, KEMPublicKeyV1](NewV1(), new([32]byte), false)
	require.Equal(t, init.ChannelBinding(), resp.ChannelBinding())
}
