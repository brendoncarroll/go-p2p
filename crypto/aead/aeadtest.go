package aead

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestK256N64(t *testing.T, s K256N64) {
	var key [32]byte
	var nonce [8]byte
	in := "hello world"
	ct := make([]byte, len(in)+s.Overhead())
	s.SealK256N64(ct, &key, nonce, []byte(in), []byte{1, 2, 3})
	pt := make([]byte, len(ct)-s.Overhead())
	err := s.OpenK256N64(pt, &key, nonce, ct, []byte{1, 2, 3})
	require.NoError(t, err)
	require.Equal(t, in, string(pt))
}

func TestK256N192(t *testing.T, s K256N192) {
	var key [32]byte
	var nonce [24]byte
	in := "hello world"
	ct := make([]byte, len(in)+s.Overhead())
	s.SealK256N192(ct, &key, &nonce, []byte(in), []byte{1, 2, 3})
	pt := make([]byte, len(ct)-s.Overhead())
	err := s.OpenK256N192(pt, &key, &nonce, ct, []byte{1, 2, 3})
	require.NoError(t, err)
	require.Equal(t, in, string(pt))
}

func TestSUV256(t *testing.T, s SUV256) {
	var suv [32]byte
	in := "hello world"
	ct := make([]byte, len(in)+s.Overhead())
	s.SealSUV256(ct, &suv, []byte(in), []byte{1, 2, 3})
	pt := make([]byte, len(ct)-s.Overhead())
	err := s.OpenSUV256(pt, &suv, ct, []byte{1, 2, 3})
	require.NoError(t, err)
	require.Equal(t, in, string(pt))
}
