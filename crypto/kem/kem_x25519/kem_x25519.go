package kem_x25519

import (
	"github.com/brendoncarroll/go-p2p/crypto/dhke"
	"github.com/brendoncarroll/go-p2p/crypto/dhkem"
)

type (
	PrivateKey = dhke.X25519Private
	PublicKey  = dhke.X25519Public
)

func New() dhkem.Scheme[PrivateKey, PublicKey] {
	return dhkem.Scheme[PrivateKey, PublicKey]{
		DH: dhke.X25519{},
	}
}
