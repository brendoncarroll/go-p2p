package p2p

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"fmt"
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
		panic(fmt.Sprintf("marshaling public key %+v: %T, %v", x, x, err))
	}
	return data
}

func ParsePublicKey(data []byte) (PublicKey, error) {
	return x509.ParsePKIXPublicKey(data)
}

func EqualPublicKeys(a, b PublicKey) bool {
	return bytes.Equal(MarshalPublicKey(a), MarshalPublicKey(b))
}

// Sign uses key to produce a signature for data.
// The digest fed to the signature algorithm also depends on purpose such that
// the purpose used to Verify must match the purpose used in Sign.
// The signature will be appended to out
func Sign(out []byte, key PrivateKey, purpose string, data []byte) ([]byte, error) {
	xof := makeXOF(purpose, data)
	return SignXOF(out, key, rand.Reader, xof)
}

// Verify checks that sig was produced by the private key corresponding to key
// and that purpose matches the purposed used to created the signature.
func Verify(key PublicKey, purpose string, data, sig []byte) error {
	xof := makeXOF(purpose, data)
	return VerifyXOF(key, xof, sig)
}

func SignXOF(out []byte, privateKey PrivateKey, rng, xof io.Reader) ([]byte, error) {
	var presig [64]byte
	if _, err := io.ReadFull(xof, presig[:]); err != nil {
		return nil, err
	}
	sig, err := privateKey.Sign(rng, presig[:], crypto.Hash(0))
	if err != nil {
		return nil, err
	}
	return append(out, sig...), nil
}

func VerifyXOF(publicKey PublicKey, xof io.Reader, sig []byte) error {
	var presig [64]byte
	if _, err := io.ReadFull(xof, presig[:]); err != nil {
		return err
	}
	valid := false
	switch key := publicKey.(type) {
	case ed25519.PublicKey:
		valid = ed25519.Verify(key, presig[:], sig)
	case *ecdsa.PublicKey:
		valid = ecdsa.VerifyASN1(key, presig[:], sig)
	case *rsa.PublicKey:
		return rsa.VerifyPKCS1v15(key, crypto.Hash(0), presig[:], sig)
	default:
		return errors.Errorf("unsupported key %T", key)
	}
	if valid {
		return nil
	}
	return ErrSignatureInvalid
}

func makeXOF(purpose string, data []byte) sha3.ShakeHash {
	xof := sha3.NewCShake256(nil, []byte(purpose))
	if _, err := xof.Write([]byte(data)); err != nil {
		panic(err)
	}
	return xof
}
