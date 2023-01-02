package p2pke2

import (
	"bytes"
	"encoding/binary"
	"errors"

	"github.com/brendoncarroll/go-p2p/crypto/kem"
	"github.com/brendoncarroll/go-tai64"
)

type Time = tai64.TAI64N

type Authenticator interface {
	// Intro is called by the Initiator.
	Intro(out []byte) []byte
	// Accept is called by the Responder on the first message.
	Accept(x []byte) bool

	// Prove is called by both sides in order to create a proof for the other party.
	Prove(out []byte, target *[64]byte) []byte
	// Verify is called by both sides in order to verify a proofs made by parties.
	Verify(target *[64]byte, proof []byte) bool
}

type Prover = func(out []byte, target *[64]byte) []byte

type Verifier = func(target *[64]byte, proof []byte) bool

func IsInitHello(x []byte) bool {
	return bytes.HasPrefix(x, []byte{0, 0, 0, 0})
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
