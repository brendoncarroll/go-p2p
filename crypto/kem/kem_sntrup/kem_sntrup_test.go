package kem_sntrup

import (
	"testing"

	"github.com/brendoncarroll/go-p2p/crypto/kem"
)

func TestSNTRUP4591761(t *testing.T) {
	kem.TestScheme[PrivateKey4591761, PublicKey4591761](t, New4591761())
}
