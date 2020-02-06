package sshswarm

import (
	"context"
	"crypto/ed25519"
	"sync"
	"testing"

	"github.com/brendoncarroll/go-p2p"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestTell(t *testing.T) {
	ctx := context.TODO()
	privKey1 := getPrivateKey(0)
	privKey2 := getPrivateKey(1)

	s1, err := New("127.0.0.1:", privKey1, nil)
	require.Nil(t, err)
	defer s1.Close()
	s2, err := New("127.0.0.1:", privKey2, nil)
	require.Nil(t, err)
	defer s2.Close()

	wg := sync.WaitGroup{}
	wg.Add(1)
	recvTell := p2p.Message{}
	s1.OnTell(func(msg *p2p.Message) {
		recvTell = *msg
		wg.Done()
	})

	err = s2.Tell(ctx, s1.LocalAddrs()[0], []byte("test"))
	require.Nil(t, err)

	wg.Wait()
	if assert.NotNil(t, recvTell.Src) {
		a1 := recvTell.Src.(*Addr)
		a2 := s2.LocalAddrs()[0].(*Addr)
		assert.Equal(t, a2.Fingerprint, a1.Fingerprint)
		assert.Equal(t, a2.IP, a2.IP)
	}
	if assert.NotNil(t, recvTell.Dst) {
		a1 := recvTell.Dst.(*Addr)
		a2 := s1.LocalAddrs()[0].(*Addr)
		assert.Equal(t, a2.Fingerprint, a1.Fingerprint)
		assert.Equal(t, a2.IP, a2.IP)
	}
	assert.Equal(t, "test", string(recvTell.Payload))
}

func getPrivateKey(i uint8) ed25519.PrivateKey {
	seed := make([]byte, ed25519.SeedSize)
	seed[0] = i
	return ed25519.NewKeyFromSeed(seed)
}
