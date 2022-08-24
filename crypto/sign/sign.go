package sign

import (
	"io"
)

// Scheme is a scheme for digital signatures
type Scheme[Private, Public any] interface {
	// Generate creates a public and private key
	Generate(rng io.Reader) (pub Public, priv Private, err error)
	// DerivePublic derives the Public key which corresponds to the private key
	DerivePublic(*Private) Public

	// Sign uses priv to produce a signature for msg and writes it to dst.
	// dst must be at least SignatureSize
	Sign(dst []byte, priv *Private, msg []byte)
	// Verify checks if sig is a valid signature produced by pub for msg
	Verify(pub *Public, msg []byte, sig []byte) bool

	// MarshalPublic marshals a public key to binary data
	MarshalPublic(Public) []byte
	// ParsePublic attempts to parse a public key from bytes
	ParsePublic([]byte) (Public, error)

	// PublicKeySize returns the size of a public key
	PublicKeySize() int
	// SignatureSize returns the size of a public key
	SignatureSize() int
}
