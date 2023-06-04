package p2pke2

import (
	"bytes"
	"encoding/binary"
	"errors"

	"github.com/brendoncarroll/go-exp/crypto/kem"
	"github.com/brendoncarroll/go-tai64"
)

type Time = tai64.TAI64N

func IsInitHello(x []byte) bool {
	return bytes.HasPrefix(x, []byte{0, 0, 0, 0})
}

type InitHello[KEMPub any] struct {
	KEMPublic KEMPub
	Rest      []byte
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

type Authenticator interface {
	// Intro is called to produce an introduction message.
	// The message is used to convince the remote party to allocate resources to communicate with us.
	Intro(out []byte) ([]byte, error)
	// Accept is used to validate an intro message and determine if it is from a known party.
	Accept(intro []byte) error

	// Prove is used to produce a proof that relates the authenticating party to the target.
	Prove(out []byte, target *[64]byte) []byte
	// Verify is used to verify that proof relates to target.
	Verify(target *[64]byte, proof []byte) error
}
