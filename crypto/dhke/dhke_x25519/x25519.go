package dhke_x25519

import (
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/curve25519"

	"github.com/brendoncarroll/go-p2p/crypto/dhke"
)

type PrivateKey = [curve25519.ScalarSize]byte

type PublicKey = [curve25519.PointSize]byte

var _ dhke.Scheme[PrivateKey, PublicKey] = Scheme{}

type Scheme struct{}

func (s Scheme) Generate(rng io.Reader) (PublicKey, PrivateKey, error) {
	priv := [32]byte{}
	if _, err := io.ReadFull(rng, priv[:]); err != nil {
		return PublicKey{}, PrivateKey{}, err
	}
	pub, err := curve25519.X25519(priv[:], curve25519.Basepoint)
	return *(*[32]byte)(pub), priv, err
}

func (s Scheme) DerivePublic(priv *[curve25519.ScalarSize]byte) [curve25519.PointSize]byte {
	pub, err := curve25519.X25519(priv[:], curve25519.Basepoint)
	if err != nil {
		panic(err)
	}
	return *(*[32]byte)(pub)
}

func (s Scheme) ComputeShared(dst []byte, priv *PrivateKey, pub *PublicKey) error {
	sh, err := curve25519.X25519(priv[:], pub[:])
	if err != nil {
		return err
	}
	if len(dst) != len(sh) {
		panic(fmt.Sprintf("shared is wrong length HAVE: %d WANT: %d", len(dst), len(sh)))
	}
	copy(dst[:], sh)
	return nil
}

func (s Scheme) MarshalPublic(x [curve25519.PointSize]byte) []byte {
	return x[:]
}

func (s Scheme) ParsePublic(x []byte) ([curve25519.PointSize]byte, error) {
	if len(x) != 32 {
		return PublicKey{}, errors.New("wrong length for public key")
	}
	return *(*[32]byte)(x), nil
}

func (s Scheme) SharedSize() int {
	return 32
}

func (s Scheme) PublicKeySize() int {
	return 32
}
