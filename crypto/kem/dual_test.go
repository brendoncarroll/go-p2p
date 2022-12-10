package kem_test

import (
	"testing"

	"github.com/brendoncarroll/go-p2p/crypto/kem"
	"github.com/brendoncarroll/go-p2p/crypto/kem/kem_sntrup"
	"github.com/brendoncarroll/go-p2p/crypto/kem/kem_x25519"
)

func TestDual(t *testing.T) {
	s := kem.Dual256[kem_x25519.PrivateKey, kem_x25519.PublicKey, kem_sntrup.PrivateKey4591761, kem_sntrup.PublicKey4591761]{
		A: kem_x25519.New(),
		B: kem_sntrup.New4591761(),
	}
	type Private = kem.DualKey[kem_x25519.PrivateKey, kem_sntrup.PrivateKey4591761]
	type Public = kem.DualKey[kem_x25519.PublicKey, kem_sntrup.PublicKey4591761]
	kem.TestScheme256[Private, Public](t, s)
}
