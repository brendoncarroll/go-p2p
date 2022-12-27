package sign

import (
	"io"
)

// Scheme is a scheme for digital signatures with variable length inputs
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
	// SignatureSize returns the size of a public key
	SignatureSize() int

	PublicKeyScheme[Public]
	PrivateKeyScheme[Private]
}

// Input512 is the input to a signature in Scheme512.
// Input512 must be high entropy.
type Input512 = [64]byte

// Scheme512 is a scheme for digital signatures on 512 bits of input.
// Schemes implementing Scheme512 can have a maximum security of 256 bits against signature collisions.
// Forging signatures for a given input can have a maximum of 512 bits of security, but most implementations typically provide less.
type Scheme512[Private, Public any] interface {
	// Generate creates a public and private key
	Generate(rng io.Reader) (pub Public, priv Private, err error)
	// DerivePublic derives the Public key which corresponds to the private key
	DerivePublic(*Private) Public

	// Sign512 uses priv to produce a signature for msg and writes it to dst.
	// dst must be at least SignatureSize
	Sign512(dst []byte, priv *Private, input *Input512)
	// Verify512 checks if sig is a valid signature produced by pub for msg
	Verify512(pub *Public, input *Input512, sig []byte) bool
	// SignatureSize returns the size of a public key
	SignatureSize() int

	PublicKeyScheme[Public]
	PrivateKeyScheme[Private]
}

type PublicKeyScheme[Public any] interface {
	// MarshalPublic marshals a public key to binary data
	// MarshalPublic panics if dst is not >= PublicKeySize()
	MarshalPublic(dst []byte, pub *Public)
	// ParsePublic attempts to parse a public key from bytes
	ParsePublic([]byte) (Public, error)
	// PublicKeySize returns the size of a public key
	PublicKeySize() int
}

type PrivateKeyScheme[Private any] interface {
	MarshalPrivate(dst []byte, priv *Private)
	ParsePrivate(x []byte) (Private, error)
	PrivateKeySize() int
}

// AppendPublicKey appends the marshaled form of pub to out, using sch to marshal the public key.
func AppendPublicKey[Public any](out []byte, sch PublicKeyScheme[Public], pub *Public) []byte {
	initLen := len(out)
	out = append(out, make([]byte, sch.PublicKeySize())...)
	sch.MarshalPublic(out[initLen:], pub)
	return out
}
