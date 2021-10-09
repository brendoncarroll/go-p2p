package p2pke

import (
	"testing"
	"time"

	"github.com/brendoncarroll/go-p2p/p2ptest"
	"github.com/stretchr/testify/require"
)

func TestHandshake(t *testing.T) {
	s1, s2 := newTestPair(t)
	var send1, send2 func(data []byte)
	send1 = func(data []byte) {
		t.Logf("%v: %q", InitToResp, data)
		_, err := s2.Deliver(nil, data, time.Now(), send1)
		require.NoError(t, err)
	}
	send2 = func(data []byte) {
		t.Logf("%v: %q", RespToInit, data)
		_, err := s1.Deliver(nil, data, time.Now(), send2)
		require.NoError(t, err)
	}

	// only one of these should do anything.
	s1.StartHandshake(send1)
	s2.StartHandshake(send2)

	require.Equal(t, s1.hs.ChannelBinding(), s2.hs.ChannelBinding())
	require.Equal(t, s1.privateKey.Public(), s2.RemoteKey())
	require.Equal(t, s2.privateKey.Public(), s1.RemoteKey())
}

func newTestPair(t *testing.T) (s1, s2 *Session) {
	s1 = NewSession(SessionParams{
		IsInit:     true,
		PrivateKey: p2ptest.NewTestKey(t, 0),
	})
	s2 = NewSession(SessionParams{
		IsInit:     false,
		PrivateKey: p2ptest.NewTestKey(t, 1),
	})
	return s1, s2
}
