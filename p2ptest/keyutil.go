package p2ptest

import (
	"crypto/ed25519"
	"encoding/binary"
	"testing"

	"github.com/brendoncarroll/go-p2p"
)

func GetTestKey(t testing.TB, i int) p2p.PrivateKey {
	// depending on testing.T is to prevent missuse.
	seed := make([]byte, 32)
	binary.BigEndian.PutUint64(seed[24:], uint64(i))
	return ed25519.NewKeyFromSeed(seed)
}
