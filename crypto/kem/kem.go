package kem

import (
	"io"
)

// SeedSize is the size of Seed in bytes
const SeedSize = 32

// Seed is used as entropy for the KEM algorithm.
type Seed = [SeedSize]byte

// Secret256 is a shared secret produced by a Scheme32.
type Secret256 = [32]byte

// Scheme256 is a Key Encapsulation Mechanism which agrees on a shared 256 bit secret key
type Scheme256[Private, Public any] interface {
	// Generate creates a new private/public key pair using entropy from rng.
	Generate(rng io.Reader) (Public, Private, error)
	// DerivePublic returns the public key corresponding to the private key
	DerivePublic(*Private) Public

	// Encapsulate writes a shared secret to ss, and a ciphertext to ct.
	// The ciphertext will decryptable by pub.
	//
	// The shared secret written to ss will be uniformly random.
	// If ct is not >= CiphertextSize(), then Encapsulate will panic
	Encapsulate(ss *Secret256, ct []byte, pub *Public, seed *Seed) error
	// Decapsulate uses priv to decrypt a ciphertext from ct, and writes the resulting shared secret to ss.
	// The shared secret written to ss will be uniformly random.
	// If ct is not == CiphertextSize(), then Encapsulate should return an error.
	Decapsulate(ss *Secret256, priv *Private, ct []byte) error

	PublicKeyScheme[Public]

	CiphertextSize() int
}

type PublicKeyScheme[Public any] interface {
	// MarshalPublic marshals pub and writes the bytes to dst.
	// If len(dst) < PublicKeySize() then MarshalPublic panics
	MarshalPublic(dst []byte, pub *Public)
	// ParsePublic attempts to parse a public key from the input, and returns a public key or error.
	ParsePublic([]byte) (Public, error)
	// PublicKeySize returns the size of the public key
	PublicKeySize() int
}

func AppendPublic[Public any](out []byte, s PublicKeyScheme[Public], pub *Public) []byte {
	initLen := len(out)
	out = append(out, make([]byte, s.PublicKeySize())...)
	s.MarshalPublic(out[initLen:], pub)
	return out
}
