package p2pke

import (
	"testing"

	"github.com/brendoncarroll/go-p2p/p2ptest"
	"github.com/stretchr/testify/require"
)

func TestHandshake(t *testing.T) {
	s1, s2 := newTestPair(t)
	s1.sendInit()

	require.Equal(t, s1.hs.ChannelBinding(), s2.hs.ChannelBinding())
	require.Equal(t, s1.privateKey.Public(), s2.remoteKey)
	require.Equal(t, s2.privateKey.Public(), s1.remoteKey)
}

func newTestPair(t *testing.T) (s1, s2 *Session) {
	pk1 := p2ptest.NewTestKey(t, 0)
	pk2 := p2ptest.NewTestKey(t, 1)
	s1 = NewSession(true, pk1, func(data []byte) {
		t.Logf("i->r %q", data)
		_, err := s2.Deliver(nil, data)
		require.NoError(t, err)
	})
	s2 = NewSession(false, pk2, func(data []byte) {
		t.Logf("r->i %q", data)
		_, err := s1.Deliver(nil, data)
		require.NoError(t, err)
	})
	return s1, s2
}
