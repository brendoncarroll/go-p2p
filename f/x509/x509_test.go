package x509

import (
	"crypto/ed25519"
	"crypto/x509"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestEd25519Parse(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)
	data, err := x509.MarshalPKIXPublicKey(pub)
	require.NoError(t, err)

	y, err := ParsePublicKey(data)
	require.NoError(t, err)
	require.Equal(t, []byte(y.Data), []byte(pub))
}

func TestEd25519Marshal(t *testing.T) {
	x := PublicKey{
		AlgorithmID: Ed25519PublicKey,
		Data:        make([]byte, 32),
	}
	data := MarshalPublicKey(nil, x)
	pub, err := x509.ParsePKIXPublicKey(data)
	require.NoError(t, err)
	require.Equal(t, []byte(x.Data), []byte(pub.(ed25519.PublicKey)))
}
