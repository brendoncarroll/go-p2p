// package dhke provides an interface for Diffie-Hellman Key Exchanges
package dhke

import (
	"io"
)

type Scheme[Private, Public any] interface {
	Generate(rng io.Reader) (Public, Private, error)
	DerivePublic(*Private) Public

	SharedSize() int
	ComputeShared(shared []byte, priv *Private, pub *Public) error

	PublicKeySize() int
	MarshalPublic(dst []byte, pub *Public)
	ParsePublic([]byte) (Public, error)

	PrivateKeySize() int
	MarshalPrivate(dst []byte, priv *Private)
	ParsePrivate([]byte) (Private, error)
}
