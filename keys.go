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
// The signature will be appended to out
func Sign(out []byte, key PrivateKey, purpose string, data []byte) ([]byte, error) {
	var digest [64]byte
	sigDigest(digest[:], purpose, data)
	var sig []byte
	var err error
	switch key := key.(type) {
	case ed25519.PrivateKey:
		sig, err = key.Sign(rand.Reader, digest[:], crypto.Hash(0))
	case *ecdsa.PrivateKey:
		sig, err = key.Sign(rand.Reader, digest[:], crypto.Hash(0))
	case *rsa.PrivateKey:
		sig, err = key.Sign(rand.Reader, digest[:], crypto.Hash(0))
	default:
		return nil, errors.Errorf("unsupported key %T", key)
	}
	return append(out, sig...), err
}

// Verify checks that sig was produced by the private key corresponding to key
// and that purpose matches the purposed used to created the signature.
func Verify(key PublicKey, purpose string, data, sig []byte) error {
	var digest [64]byte
	sigDigest(digest[:], purpose, data)
	valid := false
	switch key := key.(type) {
	case ed25519.PublicKey:
		valid = ed25519.Verify(key, digest[:], sig)
	case *ecdsa.PublicKey:
		valid = ecdsa.VerifyASN1(key, digest[:], sig)
	case *rsa.PublicKey:
		return rsa.VerifyPKCS1v15(key, crypto.Hash(0), digest[:], sig)
	default:
		return errors.Errorf("unsupported key %T", key)
	}
	if valid {
		return nil
	}
	return ErrSignatureInvalid
}

func sigDigest(out []byte, purpose string, data []byte) {
	sh := sha3.NewCShake256(nil, []byte(purpose))
	if _, err := sh.Write([]byte(data)); err != nil {
		panic(err)
	}
	if _, err := io.ReadFull(sh, out); err != nil {
		panic(err)
	}
}
