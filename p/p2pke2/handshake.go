package p2pke2

import (
	"encoding/binary"
	"errors"
	"fmt"

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
	return hs
}

func (hs *HandshakeState[XOF, KEMPriv, KEMPub]) Send(out []byte) ([]byte, error) {
	initLen := len(out)
	switch {
	case hs.index == 0 && hs.isInit:
		// InitHello
		out = kem.AppendPublic[KEMPub](out, hs.scheme.KEM, &hs.kemPub)
		hs.mixPublic(out[initLen:])
		var sigTarget [64]byte
		hs.deriveSharedKey(sigTarget[:], "1-sig-target")
		out = hs.scheme.Prove(out, &sigTarget)

	case hs.index == 1 && !hs.isInit:
		// RespHello
		// derive KEM seed
		var kemSeed kem.Seed
		hs.generateKey(kemSeed[:], "1-KEM")
		// KEM Encapsulate
		var shared kem.Secret256
		out = hs.appendKEMEncap(out, &shared, &hs.remoteKEMPub, &kemSeed)
		hs.mixSecret(&shared)
		// AEAD
		var aeadKey [32]byte
		hs.deriveSharedKey(aeadKey[:], "1-aead-key")
		out = hs.appendAEADSeal(out, &aeadKey, 1, func(ptext []byte) []byte {
			var sigTarget [64]byte
			hs.deriveSharedKey(sigTarget[:], "1-sig-target")
			ptext = hs.scheme.Prove(ptext, &sigTarget)
			return ptext
		})

	case hs.index == 2 && hs.isInit:
		// InitDone
		// AEAD
		var aeadKey [32]byte
		hs.deriveSharedKey(aeadKey[:], "2-aead-key")
		out = hs.appendAEADSeal(out, &aeadKey, 2, func(ptext []byte) []byte {
			var sigTarget [64]byte
			hs.deriveSharedKey(sigTarget[:], "2-sig-target")
			ptext = hs.scheme.Prove(ptext, &sigTarget)
			return ptext
		})

	case hs.index == 3 && !hs.isInit:
		// RespDone
		var aeadKey [32]byte
		hs.deriveSharedKey(aeadKey[:], "3-aead-key")
		out = hs.appendAEADSeal(out, &aeadKey, 3, func(ptext []byte) []byte {
			return ptext
		})

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
		if len(x) < pubKeySize {
			return ErrShortHSMsg{Index: 0, Len: len(x)}
		}
		remotePub, err := hs.scheme.KEM.ParsePublic(x[:pubKeySize])
		if err != nil {
			return err
		}
		hs.mixPublic(x[:pubKeySize])
		proof := x[pubKeySize:]
		var sigTarget [64]byte
		xof.Sum(hs.scheme.XOF, sigTarget[:], x[:pubKeySize])
		if !hs.scheme.Verify(&sigTarget, proof) {
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
		kemShared, err := hs.kemDecap(&hs.kemPriv, kemCtext)
		if err != nil {
			return err
		}
		hs.mixSecret(&kemShared)
		// AEAD open
		var aeadKey [32]byte
		hs.deriveSharedKey(aeadKey[:], "1-aead-key")
		ptext := make([]byte, 0, len(x)-hs.scheme.AEAD.Overhead())
		nonce := makeNonce(1)
		ptext, err = hs.scheme.AEAD.Open(ptext, &aeadKey, &nonce, aeadCtext, nil)
		if err != nil {
			return err
		}
		var sigTarget [64]byte
		hs.deriveSharedKey(sigTarget[:], "1-sig-target")
		if !hs.scheme.Verify(&sigTarget, ptext[:]) {
			return errors.New("verification failed")
		}
		hs.index = 2

	case hs.index == 2 && !hs.isInit:
		// InitDone
		var aeadKey [32]byte
		hs.deriveSharedKey(aeadKey[:], "2-aead-key")
		nonce := makeNonce(uint64(hs.index))
		_, err := hs.scheme.AEAD.Open(nil, &aeadKey, &nonce, x, nil)
		if err != nil {
			return err
		}
		hs.remoteKEMPub = hs.remoteKEMPub
		hs.index = 3

	case hs.index == 3 && hs.isInit:
		// RespDone
		var aeadSecret [32]byte
		hs.deriveSharedKey(aeadSecret[:], "3-aead-key")
		nonce := makeNonce(3)
		_, err := hs.scheme.AEAD.Open(nil, &aeadSecret, &nonce, x, nil)
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
func (hs *HandshakeState[XOF, KEMPriv, KEMPub]) mixSecret(secret *[32]byte) {
	hs.scheme.XOF.Absorb(&hs.shared, secret[:])
}

// mixPublic is called ot mix public state
func (hs *HandshakeState[XOF, KEMPriv, KEMPub]) mixPublic(data []byte) {
	sum := xof.Sum512(hs.scheme.XOF, data)
	hs.scheme.XOF.Absorb(&hs.shared, sum[:])
}

// deriveSharedKey writes pseudorandom bytes to dst from the shared state.
// deriveSharedKey does not affect HandshakeState.
// multiple calls with the same purpose produce the same data, unless a mix is called.
func (hs *HandshakeState[XOF, KEMPriv, KEMPub]) deriveSharedKey(dst []byte, purpose string) {
	out := hs.shared
	hs.scheme.XOF.Absorb(&out, []byte{uint8(len(purpose))})
	hs.scheme.XOF.Absorb(&out, []byte(purpose))
	hs.scheme.XOF.Expand(&out, dst)
}

// generateKey uses the seed to generate a random key.
func (hs *HandshakeState[XOF, KEMPriv, KEMPub]) generateKey(dst []byte, purpose string) {
	xof.DeriveKey256(hs.scheme.XOF, dst, &hs.seed, []byte(purpose))
}

func (hs *HandshakeState[XOF, KEMPriv, KEMPub]) appendAEADSeal(out []byte, key *[32]byte, nonce uint64, fn func(ptext []byte) []byte) []byte {
	ptext := fn(nil)
	nonceBytes := makeNonce(nonce)
	return hs.scheme.AEAD.Seal(out, key, &nonceBytes, ptext, nil)
}

func (hs *HandshakeState[XOF, KEMPriv, KEMPub]) appendKEMEncap(out []byte, shared *[32]byte, pub *KEMPub, seed *[32]byte) []byte {
	kemCtext := make([]byte, hs.scheme.KEM.CiphertextSize())
	hs.scheme.KEM.Encapsulate(shared, kemCtext, pub, seed)
	return append(out, kemCtext...)
}

func (hs *HandshakeState[XOF, KEMPriv, KEMPub]) kemDecap(priv *KEMPriv, ctext []byte) ([32]byte, error) {
	var kemShared kem.Secret256
	err := hs.scheme.KEM.Decapsulate(&kemShared, &hs.kemPriv, ctext)
	return kemShared, err
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
