package aead

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestSchemeK32N8(t *testing.T, s SchemeK32N8) {
	var key [32]byte
	var nonce [8]byte
	in := "hello world"
	ct := s.Seal(nil, &key, &nonce, []byte(in), []byte{1, 2, 3})
	pt, err := s.Open(nil, &key, &nonce, ct, []byte{1, 2, 3})
	require.NoError(t, err)
	require.Equal(t, in, string(pt))
}

func TestSchemeK32N24(t *testing.T, s SchemeK32N24) {
	var key [32]byte
	var nonce [24]byte
	in := "hello world"
	ct := s.Seal(nil, &key, &nonce, []byte(in), []byte{1, 2, 3})
	pt, err := s.Open(nil, &key, &nonce, ct, []byte{1, 2, 3})
	require.NoError(t, err)
	require.Equal(t, in, string(pt))
}
