package kem

import (
	"io"
)

const (
	// SecretSize is the size of the shared secret in bytes
	SecretSize = 32
	// SeedSize is the size of Seed in bytes
	SeedSize = 32
)

type (
	// Seed is used as entropy for the KEM algorithm.
	Seed = [SeedSize]byte
	// Secret is a shared secret produced by a KEM.
	Secret = [SecretSize]byte
)

type Scheme[Private, Public any] interface {
	// Generate creates a new private/public key pair using entropy from rng.
	Generate(rng io.Reader) (Public, Private, error)
	// DerivePublic returns the public key corresponding to the private key
	DerivePublic(*Private) Public

	// Encapsulate writes a shared secret to ss, and a ciphertext to ct.
	// The ciphertext will decryptable by pub.
	//
	// The shared secret written to ss will be uniformly random.
	// If ct is not >= CiphertextSize(), then Encapsulate will panic
	Encapsulate(ss *Secret, ct []byte, pub *Public, seed *Seed) error
	// Decapsulate uses priv to decrypt a ciphertext from ct, and writes the resulting shared secret to ss.
	// The shared secret written to ss will be uniformly random.
	// If ct is not == CiphertextSize(), then Encapsulate should return an error.
	Decapsulate(ss *Secret, priv *Private, ct []byte) error

	MarshalPublic(Public) []byte
	ParsePublic([]byte) (Public, error)

	PublicKeySize() int
	CiphertextSize() int
}
