package p2pke2

import "testing"

func TestChannelState(t *testing.T) {
	// type CS = ChannelState[XOFStateV1, KEMPrivateKeyV1, KEMPublicKeyV1, struct{}]
	// suite := NewSuiteV1()

	// var lc, rc CS
	// lc = NewChannelState(ChannelStateParams[XOFStateV1, KEMPrivateKeyV1, KEMPublicKeyV1, struct{}]{
	// 	Suite: suite,
	// })
	// rc = NewChannelState(ChannelStateParams[XOFStateV1, KEMPrivateKeyV1, KEMPublicKeyV1, struct{}]{
	// 	Suite: suite,
	// })
}

func csTransmit[XOF, KEMPriv, KEMPub, Auth any](t testing.TB, send, recv *ChannelState[XOF, KEMPriv, Auth, struct{}]) []byte {
	return nil
}
