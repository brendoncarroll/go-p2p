package p2ptest

import (
	"crypto/ed25519"
	"encoding/binary"
	"testing"
)

func NewTestKey(t testing.TB, i int) ed25519.PrivateKey {
	// depending on testing.T is to prevent missuse.
	seed := make([]byte, 32)
	binary.BigEndian.PutUint64(seed[24:], uint64(i))
	return ed25519.NewKeyFromSeed(seed)
}
