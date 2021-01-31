package p2p

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"io"

	"github.com/pkg/errors"
	"golang.org/x/crypto/sha3"
)

var ErrSignatureInvalid = errors.New("signature is invalid")

type PrivateKey = crypto.Signer

type PublicKey = crypto.PublicKey

func MarshalPublicKey(x PublicKey) []byte {
	data, err := x509.MarshalPKIXPublicKey(x)
	if err != nil {
		log.Infof("%T %+v", x, x)
		panic(err)
	}
	return data
}

func ParsePublicKey(data []byte) (PublicKey, error) {
	return x509.ParsePKIXPublicKey(data)
}

// Sign uses key to produce a signature for data.
// The digest fed to the signature algorithm also depends on purpose such that
// the purpose used to Verify must match the purpose used in Sign.
func Sign(key PrivateKey, purpose string, data []byte) ([]byte, error) {
	digest := sigDigest(purpose, data)
	switch key := key.(type) {
	case ed25519.PrivateKey:
		return key.Sign(rand.Reader, digest, crypto.Hash(0))
	case *ecdsa.PrivateKey:
		return key.Sign(rand.Reader, digest, crypto.Hash(0))
	case *rsa.PrivateKey:
		return key.Sign(rand.Reader, digest, crypto.Hash(0))
	default:
		return nil, errors.Errorf("unsupported key %T", key)
	}
}

// Verify checks that sig was produced by the private key corresponding to key
// and that purpose matches the purposed used to created the signature.
func Verify(key PublicKey, purpose string, data, sig []byte) error {
	digest := sigDigest(purpose, data)
	valid := false
	switch key := key.(type) {
	case ed25519.PublicKey:
		valid = ed25519.Verify(key, digest, sig)
	case *ecdsa.PublicKey:
		valid = ecdsa.VerifyASN1(key, digest, sig)
	case *rsa.PublicKey:
		return rsa.VerifyPKCS1v15(key, crypto.Hash(0), digest, sig)
	}
	if valid {
		return nil
	}
	return ErrSignatureInvalid
}

func sigDigest(purpose string, data []byte) []byte {
	sh := sha3.NewCShake256(nil, []byte(purpose))
	if _, err := sh.Write([]byte(data)); err != nil {
		panic(err)
	}
	digest := [64]byte{}
	if _, err := io.ReadFull(sh, digest[:]); err != nil {
		panic(err)
	}
	return digest[:]
}
