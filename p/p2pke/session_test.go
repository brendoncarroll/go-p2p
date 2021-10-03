package p2pke

import (
	"testing"

	"github.com/brendoncarroll/go-p2p/p2ptest"
	"github.com/stretchr/testify/require"
)

func TestHandshake(t *testing.T) {
	s1, s2 := newTestPair(t)
	// only one of these should do anything.
	s1.StartHandshake()
	s2.StartHandshake()

	require.Equal(t, s1.hs.ChannelBinding(), s2.hs.ChannelBinding())
	require.Equal(t, s1.privateKey.Public(), s2.RemoteKey())
	require.Equal(t, s2.privateKey.Public(), s1.RemoteKey())
}

func newTestPair(t *testing.T) (s1, s2 *Session) {
	s1 = NewSession(Params{
		IsInit:     true,
		PrivateKey: p2ptest.NewTestKey(t, 0),
		Send: func(data []byte) {
			t.Logf("i->r %q", data)
			_, err := s2.Deliver(nil, data)
			require.NoError(t, err)
		},
	})
	s2 = NewSession(Params{
		IsInit:     false,
		PrivateKey: p2ptest.NewTestKey(t, 1),
		Send: func(data []byte) {
			t.Logf("r->i %q", data)
			_, err := s1.Deliver(nil, data)
			require.NoError(t, err)
		},
	})
	return s1, s2
}
