// package dhke provides an interface for Diffie-Hellman Key Exchanges
package dhke

import (
	"io"
)

type Scheme[Private, Public any] interface {
	Generate(rng io.Reader) (Public, Private, error)
	DerivePublic(*Private) Public
	ComputeShared(shared []byte, priv *Private, pub *Public) error

	MarshalPublic(Public) []byte
	ParsePublic([]byte) (Public, error)

	SharedSize() int
	PublicKeySize() int
}
