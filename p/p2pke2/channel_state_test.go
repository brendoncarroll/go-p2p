package p2pke2

import (
	"bytes"
	"testing"

	"github.com/brendoncarroll/go-tai64"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/sha3"
)

type SessionV1 = Session[XOFStateV1, KEMPrivateKeyV1, KEMPublicKeyV1]

func TestChannelState(t *testing.T) {
	lc, rc := newChannelStates(t)
	now := tai64.Now()
	csTransmit(t, &lc, &rc, now, nil)
	csTransmit(t, &rc, &lc, now, nil)
	csTransmit(t, &lc, &rc, now, nil)
	csTransmit(t, &rc, &lc, now, nil)
	requireTransmit(t, &lc, &rc, now, []byte("hello world"))
	requireTransmit(t, &rc, &lc, now, []byte("hello world2"))
}

func TestBidiHandshake(t *testing.T) {
	lc, rc := newChannelStates(t)
	now := tai64.Now()
	// Initiators on both sides.
	csTransmit(t, &lc, nil, now, nil)
	csTransmit(t, &rc, nil, now, nil)

	csTransmit(t, &lc, &rc, now, nil)
	csTransmit(t, &rc, &lc, now, nil)
	csTransmit(t, &lc, &rc, now, nil)
	csTransmit(t, &rc, &lc, now, nil)

	requireTransmit(t, &lc, &rc, now, []byte("hello world"))
	requireTransmit(t, &rc, &lc, now, []byte("hello world2"))
}

func newChannelStates(t testing.TB) (lc, rc ChannelState[SessionV1]) {
	resetSession := func(s *SessionV1, isInit bool) {
		*s = NewSession(SessionParams[XOFStateV1, KEMPrivateKeyV1, KEMPublicKeyV1]{
			Suite:  NewSuiteV1(),
			Seed:   newSeed(t, 0),
			IsInit: isInit,
			Prove: func(out []byte, target *[64]byte) []byte {
				sum := sha3.Sum256(target[:])
				return append(out, sum[:]...)
			},
			Verify: func(target *[64]byte, proof []byte) bool {
				sum := sha3.Sum256(target[:])
				return bytes.Equal(sum[:], proof)
			},
		})
	}
	lc = NewChannelState(ChannelStateParams[SessionV1]{
		Accept: func([]byte) bool {
			return true
		},
		Reset: resetSession,
		API: func(s *SessionV1) SessionAPI {
			return s
		},
	})
	rc = NewChannelState(ChannelStateParams[SessionV1]{
		Accept: func([]byte) bool { return true },
		Reset:  resetSession,
		API: func(s *SessionV1) SessionAPI {
			return s
		},
	})
	return lc, rc
}

func requireTransmit[S any](t testing.TB, send, recv *ChannelState[S], now Time, msg []byte) {
	msg2 := csTransmit(t, send, recv, now, msg)
	require.Equal(t, msg, msg2)
}

func csTransmit[S any](t testing.TB, send, recv *ChannelState[S], now Time, msg []byte) []byte {
	var buf []byte
	if msg == nil {
		var err error
		buf, err = send.SendHandshake(nil, now)
		require.NoError(t, err)
	} else {
		var err error
		buf, err = send.Send(nil, msg, now)
		require.NoError(t, err)
	}
	if recv == nil {
		return nil
	}
	out, err := recv.Deliver(nil, buf, now)
	require.NoError(t, err)
	return out
}
