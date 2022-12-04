package multipartybox

import (
	"github.com/brendoncarroll/go-p2p/crypto/aead/aead_chacha20poly1305"
	"github.com/brendoncarroll/go-p2p/crypto/kem"
	"github.com/brendoncarroll/go-p2p/crypto/kem/kem_sntrup"
	"github.com/brendoncarroll/go-p2p/crypto/kem/kem_x25519"
	"github.com/brendoncarroll/go-p2p/crypto/sign/sig_ed25519"
)

type (
	KEMPrivateKeyV1  = kem.DualKey[kem_x25519.PrivateKey, kem_sntrup.PrivateKey4591761]
	KEMPublicKeyV1   = kem.DualKey[kem_x25519.PublicKey, kem_sntrup.PublicKey4591761]
	SignPrivateKeyV1 = sig_ed25519.PrivateKey
	SignPublicKeyV1  = sig_ed25519.PublicKey

	PrivateKeyV1 = PrivateKey[KEMPrivateKeyV1, SignPrivateKeyV1]
	PublicKeyV1  = PublicKey[KEMPublicKeyV1, SignPublicKeyV1]
	SchemeV1     = Scheme[KEMPrivateKeyV1, KEMPublicKeyV1, SignPrivateKeyV1, SignPublicKeyV1]
)

// NewV1 returns the version 1 Multiparty Box encryption scheme
func NewV1() SchemeV1 {
	return SchemeV1{
		KEM: kem.Dual[kem_x25519.PrivateKey, kem_x25519.PublicKey, kem_sntrup.PrivateKey4591761, kem_sntrup.PublicKey4591761]{
			A: kem_x25519.New(),
			B: kem_sntrup.New4591761(),
		},
		Sign: sig_ed25519.New(),
		AEAD: aead_chacha20poly1305.SUV{},
	}
}
