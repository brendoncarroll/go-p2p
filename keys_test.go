package p2p

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestSignVerify(t *testing.T) {
	keys := []PrivateKey{
		newEd25519(),
		newRSA(),
		newECDSA(),
	}

	testData := "test data"
	tamperedData := "test data :)"

	for _, priv := range keys {
		pub := priv.Public()
		sig, err := Sign(nil, priv, "test", []byte(testData))
		require.NoError(t, err)
		err = Verify(pub, "test", []byte(testData), sig)
		require.NoError(t, err)
		err = Verify(pub, "test", []byte(tamperedData), sig)
		require.Error(t, err)
	}
}

func newEd25519() PrivateKey {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}
	return priv
}

func newRSA() PrivateKey {
	priv, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		panic(err)
	}
	return priv
}

func newECDSA() PrivateKey {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}
	return priv
}
