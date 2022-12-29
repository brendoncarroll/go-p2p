package p2pke2

import (
	"strings"

	"github.com/brendoncarroll/go-p2p/crypto/aead"
	"github.com/brendoncarroll/go-p2p/crypto/aead/aead_chacha20poly1305"
	"github.com/brendoncarroll/go-p2p/crypto/kem"
	"github.com/brendoncarroll/go-p2p/crypto/kem/kem_sntrup"
	"github.com/brendoncarroll/go-p2p/crypto/kem/kem_x25519"
	"github.com/brendoncarroll/go-p2p/crypto/xof"
	"github.com/brendoncarroll/go-p2p/crypto/xof/xof_sha3"
)

// Suite is a set of cryptographic primitives used to establish and send data over a secure channel
type Suite[XOF, KEMPriv, KEMPub any] struct {
	Name string
	XOF  xof.Scheme[XOF]
	AEAD aead.SchemeK256N64
	KEM  kem.Scheme256[KEMPriv, KEMPub]
}

func MakeName(xof, aead, kem string) string {
	return strings.Join([]string{xof, aead, kem}, "_")
}

type (
	KEMPrivateKeyV1 = kem.DualKey[kem_x25519.PrivateKey, kem_sntrup.PrivateKey4591761]
	KEMPublicKeyV1  = kem.DualKey[kem_x25519.PublicKey, kem_sntrup.PublicKey4591761]
	XOFStateV1      = xof_sha3.SHAKE256State

	XOFV1 = xof_sha3.SHAKE256
)

type SuiteV1 = Suite[XOFStateV1, KEMPrivateKeyV1, KEMPublicKeyV1]

func NewSuiteV1() SuiteV1 {
	xofScheme := xof_sha3.SHAKE256{}
	return SuiteV1{
		Name: MakeName("shake256", "chacha20poly1305", dualKEMName("x25519", "sntrup4591761")),
		XOF:  xofScheme,
		AEAD: aead_chacha20poly1305.N64{},
		KEM: kem.Dual256[kem_x25519.PrivateKey, kem_x25519.PublicKey, kem_sntrup.PrivateKey4591761, kem_sntrup.PublicKey4591761, XOFStateV1]{
			L:   kem_x25519.New(),
			R:   kem_sntrup.New4591761(),
			XOF: xofScheme,
		},
	}
}

func dualKEMName(left, right string) string {
	return strings.Join([]string{"dual", left, right}, "-")
}
