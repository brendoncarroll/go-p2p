package p2pke

import (
	"testing"

	"github.com/brendoncarroll/go-p2p/p2ptest"
	"github.com/stretchr/testify/require"
)

func TestHandshake(t *testing.T) {
	noOpDeliver := func([]byte) {}
	s1, s2 := newTestPair(t, noOpDeliver, noOpDeliver)
	// only one of these should do anything.
	s1.StartHandshake()
	s2.StartHandshake()

	require.Equal(t, s1.hs.ChannelBinding(), s2.hs.ChannelBinding())
	require.Equal(t, s1.privateKey.Public(), s2.RemoteKey())
	require.Equal(t, s2.privateKey.Public(), s1.RemoteKey())
}

func newTestPair(t *testing.T, d1, d2 func([]byte)) (s1, s2 *Session) {
	s1 = NewSession(Params{
		IsInit:     true,
		PrivateKey: p2ptest.NewTestKey(t, 0),
		Send: func(data []byte) {
			t.Logf("%v: %q", InitToResp, data)
			out, err := s2.Deliver(nil, data)
			require.NoError(t, err)
			if out != nil {
				d1(out)
			}
		},
	})
	s2 = NewSession(Params{
		IsInit:     false,
		PrivateKey: p2ptest.NewTestKey(t, 1),
		Send: func(data []byte) {
			t.Logf("%v: %q", RespToInit, data)
			out, err := s1.Deliver(nil, data)
			require.NoError(t, err)
			if out != nil {
				d2(out)
			}
		},
	})
	return s1, s2
}
