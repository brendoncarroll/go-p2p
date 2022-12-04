package kem_x25519

import (
	"github.com/brendoncarroll/go-p2p/crypto/dhke/dhke_x25519"
	"github.com/brendoncarroll/go-p2p/crypto/dhkem"
)

type (
	PrivateKey = dhke_x25519.PrivateKey
	PublicKey  = dhke_x25519.PublicKey
)

func New() dhkem.Scheme[PrivateKey, PublicKey] {
	return dhkem.Scheme[PrivateKey, PublicKey]{
		DH: dhke_x25519.Scheme{},
	}
}
