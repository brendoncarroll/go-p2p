package dhke

import (
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/curve25519"
)

type X25519Private = [curve25519.ScalarSize]byte

type X25519Public = [curve25519.PointSize]byte

var _ Scheme[X25519Private, X25519Public] = X25519{}

type X25519 struct{}

func (s X25519) Generate(rng io.Reader) (X25519Public, X25519Private, error) {
	priv := [32]byte{}
	if _, err := io.ReadFull(rng, priv[:]); err != nil {
		return X25519Public{}, X25519Private{}, err
	}
	pub, err := curve25519.X25519(priv[:], curve25519.Basepoint)
	return *(*[32]byte)(pub), priv, err
}

func (s X25519) DerivePublic(priv *[curve25519.ScalarSize]byte) [curve25519.PointSize]byte {
	pub, err := curve25519.X25519(priv[:], curve25519.Basepoint)
	if err != nil {
		panic(err)
	}
	return *(*[32]byte)(pub)
}

func (s X25519) ComputeShared(dst []byte, priv *X25519Private, pub *X25519Public) error {
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

func (s X25519) MarshalPublic(x [curve25519.PointSize]byte) []byte {
	return x[:]
}

func (s X25519) ParsePublic(x []byte) ([curve25519.PointSize]byte, error) {
	if len(x) != 32 {
		return X25519Public{}, errors.New("wrong length for public key")
	}
	return *(*[32]byte)(x), nil
}

func (s X25519) SharedSize() int {
	return 32
}

func (s X25519) PublicKeySize() int {
	return 32
}
