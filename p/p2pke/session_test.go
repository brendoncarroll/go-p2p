package p2pke

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"go.brendoncarroll.net/p2p/f/x509"
	"go.brendoncarroll.net/p2p/p2ptest"
)

func TestHandshake(t *testing.T) {
	s1, s2 := newTestPair(t)
	m0 := s1.Handshake(nil)
	logMsg(t, InitToResp, m0)
	_, m1, err := s2.Deliver(nil, m0, time.Now())
	require.NoError(t, err)
	logMsg(t, RespToInit, m1)
	_, m2, err := s1.Deliver(nil, m1, time.Now())
	require.NoError(t, err)
	logMsg(t, InitToResp, m2)
	_, m3, err := s2.Deliver(nil, m2, time.Now())
	require.NoError(t, err)
	logMsg(t, RespToInit, m3)
	_, m4, err := s1.Deliver(nil, m3, time.Now())
	require.NoError(t, err)
	require.Len(t, m4, 0)

	require.Equal(t, s1.hs.ChannelBinding(), s2.hs.ChannelBinding())
	require.Equal(t, s1.LocalKey(), s2.RemoteKey())
	require.Equal(t, s2.LocalKey(), s1.RemoteKey())
}

func TestHandshakeRepeats(t *testing.T) {
	s1, s2 := newTestPair(t)
	var m1, m2, m3, m4 []byte
	var err error
	var isApp bool
	const N = 10

	for i := 0; i < N; i++ {
		m0 := s1.Handshake(nil)
		//logMsg(t, InitToResp, m0)
		isApp, m1, err = s2.Deliver(nil, m0, time.Now())
		require.NoError(t, err)
		require.False(t, isApp)
	}
	for i := 0; i < N; i++ {
		//logMsg(t, RespToInit, m1)
		isApp, m2, err = s1.Deliver(nil, m1, time.Now())
		require.NoError(t, err)
		require.False(t, isApp)
	}
	for i := 0; i < N; i++ {
		//logMsg(t, InitToResp, m2)
		isApp, m3, err = s2.Deliver(nil, m2, time.Now())
		require.NoError(t, err)
		require.False(t, isApp)
	}
	for i := 0; i < N; i++ {
		//logMsg(t, InitToResp, m2)
		isApp, m4, err = s1.Deliver(nil, m3, time.Now())
		require.NoError(t, err)
		require.False(t, isApp)
		require.Len(t, m4, 0)
	}

	require.Equal(t, s1.hs.ChannelBinding(), s2.hs.ChannelBinding())
	require.Equal(t, s1.LocalKey(), s2.RemoteKey())
	require.Equal(t, s2.LocalKey(), s1.RemoteKey())
}

func logMsg(t *testing.T, direction Direction, data []byte) {
	t.Logf("%v: %q", direction, data)
}

func newTestPair(t *testing.T) (s1, s2 *Session) {
	reg := x509.DefaultRegistry()
	s1 = NewSession(SessionConfig{
		IsInit:      true,
		Registry:    reg,
		PrivateKey:  newTestKey(t, 0),
		Now:         time.Now(),
		Logger:      newTestLogger(t),
		RejectAfter: RejectAfterTime,
	})
	s2 = NewSession(SessionConfig{
		IsInit:      false,
		Registry:    reg,
		PrivateKey:  newTestKey(t, 1),
		Now:         time.Now(),
		Logger:      newTestLogger(t),
		RejectAfter: RejectAfterTime,
	})
	return s1, s2
}

func newTestLogger(t testing.TB) *zap.Logger {
	l, _ := zap.NewDevelopment()
	return l
}

func newTestKey(t testing.TB, i int) x509.PrivateKey {
	reg := x509.DefaultRegistry()
	algoID, signer := x509.SignerFromStandard(p2ptest.NewTestKey(t, i))
	priv, err := reg.StoreSigner(algoID, signer)
	require.NoError(t, err)
	return priv
}
