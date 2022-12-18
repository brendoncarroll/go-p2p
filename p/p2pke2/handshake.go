package p2pke2

import (
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/brendoncarroll/go-tai64"

	"github.com/brendoncarroll/go-p2p/crypto/kem"
	"github.com/brendoncarroll/go-p2p/crypto/xof"
)

type HandshakeState[XOF, KEMPriv, KEMPub any] struct {
	// scheme is the set of cryptographic primitives used for the handshake.
	scheme Scheme[XOF, KEMPriv, KEMPub]
	// isInit is true if this state is for the initiator
	isInit bool
	// seed is used to generate all random values
	seed [32]byte

	// index is the position in the handshake state machine.
	index        uint8
	shared       XOF
	kemPriv      KEMPriv
	kemPub       KEMPub
	remoteKEMPub KEMPub
}

func NewHandshakeState[XOF, KEMPriv, KEMPub any](
	scheme Scheme[XOF, KEMPriv, KEMPub],
	seed *[32]byte,
	isInit bool,
) HandshakeState[XOF, KEMPriv, KEMPub] {
	rng := xof.NewRand256(scheme.XOF, seed)
	kemPub, kemPriv, err := scheme.KEM.Generate(&rng)
	if err != nil {
		panic(err)
	}
	hs := HandshakeState[XOF, KEMPriv, KEMPub]{
		seed:    *seed,
		kemPriv: kemPriv,
		kemPub:  kemPub,
	}
	hs.mixPublic([]byte(scheme.Name))
	hs.mixPublic([]byte{uint8(len(scheme.Name))})
	return hs
}

func (hs *HandshakeState[XOF, KEMPriv, KEMPub]) Send(out []byte) ([]byte, error) {
	initLen := len(out)
	switch {
	case hs.index == 0 && hs.isInit:
		// InitHello
		out = kem.AppendPublic(out, hs.scheme.KEM, &hs.kemPub)
		out = append(out, hs.now.Marshal()...)
		var sigTarget [64]byte
		xof.Sum(hs.scheme.XOF, sigTarget[:], out[initLen:])
		out = hs.scheme.Prove(out, &sigTarget)

	case hs.index == 1 && !hs.isInit:
		// RespHello
		// derive KEM seed
		var kemSeed kem.Seed
		xof.DeriveKey256(hs.scheme.XOF, kemSeed[:], &hs.seed, []byte("1-KEM"))
		// KEM Encapsulate
		var shared kem.Secret256
		kemCtext := make([]byte, hs.scheme.KEM.CiphertextSize())
		hs.scheme.KEM.Encapsulate(&shared, kemCtext, &hs.remoteKEMPub, &kemSeed)
		hs.mixSecret(shared[:])
		out = append(out, kemCtext...)
		// AEAD
		var ptext []byte
		var sigTarget [64]byte
		hs.deriveKey(sigTarget[:], "1-sig-target")
		ptext = hs.scheme.Prove(ptext, &sigTarget)
		var aeadKey [32]byte
		hs.deriveKey(aeadKey[:], "1-aead-key")
		nonce := makeNonce(1)
		out = hs.scheme.AEAD.Seal(out, &aeadKey, &nonce, ptext)

	case hs.index == 2 && hs.isInit:
		// InitDone
		// derive KEM seed
		var kemSeed kem.Seed
		xof.DeriveKey256(hs.scheme.XOF, kemSeed[:], &hs.seed, []byte("2-KEM"))
		// KEM Encapsulate
		var kemShared kem.Secret256
		kemCtext := make([]byte, hs.scheme.KEM.CiphertextSize())
		hs.scheme.KEM.Encapsulate(&kemShared, kemCtext, &hs.remoteKEMPub, &kemSeed)
		hs.mixSecret(kemShared[:])
		out = append(out, kemCtext...)
		// AEAD
		var ptext []byte
		var aeadKey [32]byte
		hs.deriveKey(aeadKey[:], "2-aead-key")
		var sigTarget [64]byte
		hs.deriveKey(sigTarget[:], "2-sig-target")
		ptext = hs.scheme.Prove(ptext, &sigTarget)
		nonce := makeNonce(2)
		out = hs.scheme.AEAD.Seal(out, &aeadKey, &nonce, ptext)

	case hs.index == 3 && !hs.isInit:
		// RespDone
		var aeadKey [32]byte
		hs.deriveKey(aeadKey[:], "3-aead-key")
		nonce := makeNonce(3)
		out = hs.scheme.AEAD.Seal(out, &aeadKey, &nonce, nil)

	default:
		panic(hs.index)
	}
	hs.mixPublic(out[initLen:])
	return out, nil
}

func (hs *HandshakeState[XOF, KEMPriv, KEMPub]) Deliver(x []byte) error {
	switch {
	case hs.index == 0 && !hs.isInit:
		// InitHello
		pubKeySize := hs.scheme.KEM.PublicKeySize()
		if len(x) < pubKeySize+12 {
			return ErrShortHSMsg{Index: 0, Len: len(x)}
		}
		remotePub, err := hs.scheme.KEM.ParsePublic(x[:pubKeySize])
		if err != nil {
			return err
		}
		helloTime, err := tai64.ParseN(x[pubKeySize : pubKeySize+12])
		if err != nil {
			return err
		}
		proof := x[pubKeySize+12:]
		var sigTarget [64]byte
		xof.Sum(hs.scheme.XOF, sigTarget[:], x)
		if !hs.scheme.Verifier(hs.remoteInfo, proof, &sigTarget) {
			return errors.New("verification failed")
		}
		hs.remoteKEMPub = remotePub
		hs.index = 1

	case hs.index == 1 && hs.isInit:
		// RespHello
		kemCtextSize := hs.scheme.KEM.CiphertextSize()
		if len(x) < kemCtextSize {
			return ErrShortHSMsg{Index: hs.index, Len: len(x)}
		}
		kemCtext := x[:kemCtextSize]
		aeadCtext := x[kemCtextSize:]
		// KEM Decapsulate
		var kemShared kem.Secret256
		if err := hs.scheme.KEM.Decapsulate(&kemShared, &hs.kemPriv, kemCtext); err != nil {
			return err
		}
		var aeadKey [32]byte
		hs.deriveKey(aeadKey[:], "1-aead-key")
		ptext := make([]byte, 0, len(x)-hs.scheme.AEAD.Overhead())
		ptext, err := hs.scheme.AEAD.Open(ptext, &aeadKey, new([8]byte), aeadCtext)
		if err != nil {
			return err
		}
		remoteKEMPub, err := hs.scheme.KEM.ParsePublicKey(ptext[:hs.scheme.KEM.PublicKeySize()])
		if err != nil {
			return err
		}
		var sigTarget [64]byte
		hs.deriveKey(sigTarget[:], "1-sig-target")
		hs.scheme.Verify(&hs.remoteInfo, &sigTarget, ptext[:])
		hs.remoteKEMPub = remoteKEMPub
		hs.index = 2

	case hs.index == 2 && !hs.isInit:
		// InitDone
		kemCtextSize := hs.scheme.KEM.CiphertextSize()
		if len(x) < kemCtextSize {
			return ErrShortHSMsg{Index: hs.index, Len: len(x)}
		}
		kemCtext := x[:kemCtextSize]
		aeadCtext := x[kemCtextSize:]
		var kemShared kem.Secret256
		if err := hs.scheme.KEM.Decapsulate(&kemShared, &hs.kemPriv, kemCtext); err != nil {
			return err
		}
		hs.mixSecret(kemShared[:])
		var aeadKey [32]byte
		hs.deriveKey(aeadKey[:], "2-aead-key")
		nonce := makeNonce(uint64(hs.index))
		ptext, err := hs.scheme.AEAD.Open(nil, &aeadKey, &nonce, aeadCtext)
		if err != nil {
			return err
		}
		hs.remoteKEMPub = hs.remoteKEMPub
		hs.index = 3

	case hs.index == 3 && hs.isInit:
		// RespDone
		var aeadSecret [32]byte
		hs.deriveKey(aeadSecret[:], "3-aead-key")
		nonce := makeNonce(3)
		_, err := hs.scheme.AEAD.Open(nil, &aeadSecret, &nonce, x)
		if err != nil {
			return err
		}
		hs.index = 4

	default:
		return errors.New("out of order handshake message")
	}
	hs.mixPublic(x)
	return nil
}

func (hs *HandshakeState[XOF, KEMPriv, KEMPub]) IsDone() bool {
	return hs.index >= 4
}

func (hs *HandshakeState[XOF, KEMPriv, KEMPub]) ChannelBinding() (ret [64]byte) {
	out := hs.shared
	hs.scheme.XOF.Expand(&out, ret[:])
	return ret
}

func (hs *HandshakeState[XOF, KEMPriv, KEMPub]) Split() (inbound, outbound [32]byte) {
	if hs.index < 4 {
		return inbound, outbound
	}
	return inbound, outbound
}

func (hs *HandshakeState[XOF, KEMPriv, KEMPub]) Index() uint8 {
	return hs.index
}

func (hs *HandshakeState[XOF, KEMPriv, KEMPub]) absorb(x []byte) {
	hs.scheme.XOF.Absorb(&hs.shared, x)
}

// mixSecret is called to mix secret state
func (hs *HandshakeState[XOF, KEMPriv, KEMPub]) mixSecret(x []byte) {
	hs.scheme.XOF.Absorb(&hs.shared, x)
}

// mixPublic is called ot mix public state
func (hs *HandshakeState[XOF, KEMPriv, KEMPub]) mixPublic(x []byte) {
	hs.scheme.XOF.Absorb(&hs.shared, x)
}

func (hs *HandshakeState[XOF, KEMPriv, KEMPub]) deriveKey(dst []byte, purpose string) {
	out := hs.shared
	hs.scheme.XOF.Absorb(&out, []byte(purpose))
	hs.scheme.XOF.Absorb(&out, []byte{uint8(len(purpose))})
	hs.scheme.XOF.Expand(&out, dst)
}

func (hs *HandshakeState[XOF, KEMPriv, KEMPub]) forward() {
	var x [64]byte
	hs.scheme.XOF.Expand(&hs.shared, x[:])
	hs.scheme.XOF.Reset(&hs.shared)
	hs.scheme.XOF.Absorb(&hs.shared, x[:])
}

func makeNonce(x uint64) (ret [8]byte) {
	binary.BigEndian.PutUint64(ret[:], x)
	return ret
}

type ErrOOOHandshake struct {
	IsInit bool
	Index  uint8
}

func (e ErrOOOHandshake) Error() string {
	return fmt.Sprintf("handshake state machine not expecting message init=%v index=%v", e.IsInit, e.Index)
}

type ErrShortHSMsg struct {
	Index uint8
	Len   int
}

func (e ErrShortHSMsg) Error() string {
	return fmt.Sprintf("message too short (len=%d) to be in handshake (index=%d)", e.Len, e.Index)
}
