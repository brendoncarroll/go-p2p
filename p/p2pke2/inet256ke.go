package p2pke2

import (
	"encoding/binary"
	"errors"
	"strings"

	"github.com/brendoncarroll/go-p2p/crypto/aead"
	"github.com/brendoncarroll/go-p2p/crypto/aead/aead_chacha20poly1305"
	"github.com/brendoncarroll/go-p2p/crypto/kem"
	"github.com/brendoncarroll/go-p2p/crypto/kem/kem_sntrup"
	"github.com/brendoncarroll/go-p2p/crypto/kem/kem_x25519"
	"github.com/brendoncarroll/go-p2p/crypto/xof"
	"github.com/brendoncarroll/go-p2p/crypto/xof/xof_sha3"
)

type Authenticator interface {
	Prove(out []byte, target *[64]byte) []byte
	Verify(target *[64]byte, proof []byte) bool
}

type Prover func(out []byte, target *[64]byte) []byte

type Verifier func(target *[64]byte, proof []byte) bool

type Scheme[XOF, KEMPriv, KEMPub any] struct {
	Name   string
	XOF    xof.Scheme[XOF]
	AEAD   aead.SchemeK256N64
	KEM    kem.Scheme256[KEMPriv, KEMPub]
	Prove  Prover
	Verify Verifier
}

type (
	KEMPrivateKeyV1 = kem.DualKey[kem_x25519.PrivateKey, kem_sntrup.PrivateKey4591761]
	KEMPublicKeyV1  = kem.DualKey[kem_x25519.PublicKey, kem_sntrup.PublicKey4591761]
	XOFStateV1      = xof_sha3.SHAKE256State
	XOFV1           = xof_sha3.SHAKE256
)

type SchemeV1 = Scheme[XOFStateV1, KEMPrivateKeyV1, KEMPublicKeyV1]

func NewV1() SchemeV1 {
	xofScheme := xof_sha3.SHAKE256{}
	return SchemeV1{
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

type InitHello[KEMPub any] struct {
	KEMPublic KEMPub
	Proof     []byte
}

func ParseInitHello[KEMPub any](sch kem.PublicKeyScheme[KEMPub], x []byte) (*InitHello[KEMPub], error) {
	if len(x) < 4+sch.PublicKeySize() {
		return nil, errors.New("sch < public key size")
	}
	counter := binary.BigEndian.Uint32(x[0:4])
	if counter != 0 {
		return nil, errors.New("not a InitHello message")
	}
	return &InitHello[KEMPub]{}, nil
}

func MakeName(xof, aead, kem string) string {
	return strings.Join([]string{xof, aead, kem}, "_")
}

func dualKEMName(left, right string) string {
	return strings.Join([]string{"dual", left, right}, "-")
}
