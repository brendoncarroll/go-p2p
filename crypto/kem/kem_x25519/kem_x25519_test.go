package kem_x25519

import (
	"testing"

	"github.com/brendoncarroll/go-p2p/crypto/kem"
)

func TestX25519(t *testing.T) {
	kem.TestScheme[PrivateKey, PublicKey](t, New())
}
