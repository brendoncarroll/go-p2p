package p2pke2

import (
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/brendoncarroll/go-p2p/crypto/aead"
	"github.com/brendoncarroll/go-p2p/crypto/kem"
	"github.com/brendoncarroll/go-p2p/crypto/xof"
)

type HandshakeParams[XOF, KEMPriv, KEMPub any] struct {
	Suite  Suite[XOF, KEMPriv, KEMPub]
	Seed   *[32]byte
	IsInit bool

	Prove  func(out []byte, target *[64]byte) []byte
	Verify func(target *[64]byte, proof []byte) bool
}

type HandshakeState[XOF, KEMPriv, KEMPub any] struct {
	params      HandshakeParams[XOF, KEMPriv, KEMPub]
	seed        [32]byte
	initialized bool

	// index is the position in the handshake state machine.
	index   uint8
	state   XOF
	kemPriv KEMPriv
	kemPub  KEMPub
}

func NewHandshakeState[XOF, KEMPriv, KEMPub any](params HandshakeParams[XOF, KEMPriv, KEMPub]) HandshakeState[XOF, KEMPriv, KEMPub] {
	hs := HandshakeState[XOF, KEMPriv, KEMPub]{
		params:      params,
		seed:        *params.Seed,
		initialized: true,

		state: params.Suite.XOF.New(),
	}
	if params.IsInit {
		var kemKeyGenSeed [32]byte
		xof.DeriveKey256(params.Suite.XOF, kemKeyGenSeed[:], params.Seed, []byte("KEM-keygen"))
		rng := xof.NewRand256(params.Suite.XOF, &kemKeyGenSeed)
		var err error
		hs.kemPub, hs.kemPriv, err = params.Suite.KEM.Generate(&rng)
		if err != nil {
			panic(err)
		}
	}
	hs.mixPublic([]byte(params.Suite.Name))
	return hs
}

func (hs *HandshakeState[XOF, KEMPriv, KEMPub]) Send(out []byte) ([]byte, error) {
	initLen := len(out)
	switch {
	case hs.index == 0 && hs.params.IsInit:
		// InitHello
		out = kem.AppendPublic[KEMPub](out, hs.KEM(), &hs.kemPub)

	case hs.index == 1 && !hs.params.IsInit:
		// RespHello
		// derive KEM seed
		var kemSeed kem.Seed
		hs.generateKey(kemSeed[:], "1-KEM")
		// KEM Encapsulate
		var shared kem.Secret256
		out = hs.appendKEMEncap(out, &shared, &hs.kemPub, &kemSeed)
		hs.mixSecret(&shared)
		// AEAD
		var aeadKey [32]byte
		hs.deriveSharedKey(aeadKey[:], "1-aead-key")
		out = hs.appendAEADSeal(out, &aeadKey, 1, func(ptext []byte) []byte {
			var sigTarget [64]byte
			hs.deriveSharedKey(sigTarget[:], "1-sig-target")
			ptext = hs.params.Prove(ptext, &sigTarget)
			return ptext
		})

	case hs.index == 2 && hs.params.IsInit:
		// InitDone
		// AEAD
		var aeadKey [32]byte
		hs.deriveSharedKey(aeadKey[:], "2-aead-key")
		out = hs.appendAEADSeal(out, &aeadKey, 2, func(ptext []byte) []byte {
			var sigTarget [64]byte
			hs.deriveSharedKey(sigTarget[:], "2-sig-target")
			ptext = hs.params.Prove(ptext, &sigTarget)
			return ptext
		})

	case hs.index == 3 && !hs.params.IsInit:
		// RespDone
		var aeadKey [32]byte
		hs.deriveSharedKey(aeadKey[:], "3-aead-key")
		out = hs.appendAEADSeal(out, &aeadKey, 3, func(ptext []byte) []byte {
			return ptext
		})

	default:
		return nil, ErrOOOHandshake{
			IsSend: true,
			Index:  hs.index,
			IsInit: hs.params.IsInit,
		}
	}
	hs.index++
	hs.mixPublic(out[initLen:])
	return out, nil
}

func (hs *HandshakeState[XOF, KEMPriv, KEMPub]) Deliver(x []byte) error {
	switch {
	case hs.index == 0 && !hs.params.IsInit:
		// InitHello
		pubKeySize := hs.KEM().PublicKeySize()
		if len(x) < pubKeySize {
			return ErrShortHSMsg{Index: 0, Len: len(x)}
		}
		remotePub, err := hs.KEM().ParsePublic(x[:pubKeySize])
		if err != nil {
			return err
		}
		hs.kemPub = remotePub
		hs.index = 1

	case hs.index == 1 && hs.params.IsInit:
		// RespHello
		kemCtextSize := hs.KEM().CiphertextSize()
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
		ptext, err := hs.aeadOpen(&aeadKey, 1, aeadCtext)
		if err != nil {
			return err
		}
		var sigTarget [64]byte
		hs.deriveSharedKey(sigTarget[:], "1-sig-target")
		if !hs.params.Verify(&sigTarget, ptext[:]) {
			return errors.New("verification failed")
		}
		hs.index = 2

	case hs.index == 2 && !hs.params.IsInit:
		// InitDone
		var aeadKey [32]byte
		hs.deriveSharedKey(aeadKey[:], "2-aead-key")
		_, err := hs.aeadOpen(&aeadKey, 2, x)
		if err != nil {
			return err
		}
		hs.index = 3

	case hs.index == 3 && hs.params.IsInit:
		// RespDone
		var aeadKey [32]byte
		hs.deriveSharedKey(aeadKey[:], "3-aead-key")
		_, err := hs.aeadOpen(&aeadKey, 3, x)
		if err != nil {
			return err
		}
		hs.index = 4

	default:
		return ErrOOOHandshake{
			IsSend: false,
			Index:  hs.index,
			IsInit: hs.params.IsInit,
		}
	}
	hs.mixPublic(x)
	return nil
}

func (hs *HandshakeState[XOF, KEMPriv, KEMPub]) IsDone() bool {
	// if initialized is false then the handshake has been zeroed.
	return hs.index >= 4 || !hs.initialized
}

func (hs *HandshakeState[XOF, KEMPriv, KEMPub]) ShouldSend() bool {
	shouldSend := (hs.params.IsInit && hs.index%2 == 0) || (!hs.params.IsInit && hs.index%2 == 1)
	return hs.IsDone() && shouldSend
}

func (hs *HandshakeState[XOF, KEMPriv, KEMPub]) ChannelBinding() (ret [64]byte) {
	hs.deriveSharedKey(ret[:], "channel-binding")
	return ret
}

func (hs *HandshakeState[XOF, KEMPriv, KEMPub]) Split() (inbound, outbound [32]byte) {
	if hs.index < 4 {
		panic("split called before end of handshake")
	}
	const (
		respToInit = "resp->init"
		initToResp = "init->resp"
	)
	if hs.params.IsInit {
		hs.deriveSharedKey(inbound[:], respToInit)
		hs.deriveSharedKey(outbound[:], initToResp)
	} else {
		hs.deriveSharedKey(inbound[:], initToResp)
		hs.deriveSharedKey(outbound[:], respToInit)
	}
	return inbound, outbound
}

func (hs *HandshakeState[XOF, KEMPriv, KEMPub]) Index() uint8 {
	return hs.index
}

// XOF returns the XOF used by this handshake
func (hs *HandshakeState[XOF, KEMPriv, KEMPub]) XOF() xof.Scheme[XOF] {
	return hs.params.Suite.XOF
}

// KEM returns the KEM used by this handshake
func (hs *HandshakeState[XOF, KEMPriv, KEMPub]) KEM() kem.Scheme256[KEMPriv, KEMPub] {
	return hs.params.Suite.KEM
}

// AEAD returns the AEAD used by this handshake
func (hs *HandshakeState[XOF, KEMPriv, KEMPub]) AEAD() aead.K256N64 {
	return hs.params.Suite.AEAD
}

// Zeros the memory in the HandshakeState
func (hs *HandshakeState[XOF, KEMPriv, KEMPub]) Zero() {
	*hs = HandshakeState[XOF, KEMPriv, KEMPub]{}
}

func (hs *HandshakeState[XOF, KEMPriv, KEMPub]) IsInitiator() bool {
	return hs.params.IsInit
}

// mixSecret is called to mix secret state
func (hs *HandshakeState[XOF, KEMPriv, KEMPub]) mixSecret(secret *[32]byte) {
	hs.XOF().Absorb(&hs.state, secret[:])
}

// mixPublic is called ot mix public state
func (hs *HandshakeState[XOF, KEMPriv, KEMPub]) mixPublic(data []byte) {
	sum := xof.Sum512(hs.XOF(), data)
	hs.XOF().Absorb(&hs.state, sum[:])
}

// deriveSharedKey writes pseudorandom bytes to dst from the shared state.
// deriveSharedKey does not affect HandshakeState.
// multiple calls with the same purpose produce the same data, unless a mix is called.
func (hs *HandshakeState[XOF, KEMPriv, KEMPub]) deriveSharedKey(dst []byte, purpose string) {
	out := hs.state
	hs.XOF().Absorb(&out, []byte{uint8(len(purpose))})
	hs.XOF().Absorb(&out, []byte(purpose))
	hs.XOF().Expand(&out, dst)
}

// generateKey uses the seed to generate a random key.
func (hs *HandshakeState[XOF, KEMPriv, KEMPub]) generateKey(dst []byte, purpose string) {
	xof.DeriveKey256(hs.XOF(), dst, &hs.seed, []byte(purpose))
}

func (hs *HandshakeState[XOF, KEMPriv, KEMPub]) appendAEADSeal(out []byte, key *[32]byte, nonce uint64, fn func(ptext []byte) []byte) []byte {
	ptext := fn(nil)
	nonceBytes := makeNonce(nonce)
	return aead.AppendSealK256N64(out, hs.AEAD(), key, nonceBytes, ptext, nil)
}

func (hs *HandshakeState[XOF, KEMPriv, KEMPub]) appendKEMEncap(out []byte, shared *[32]byte, pub *KEMPub, seed *[32]byte) []byte {
	kemCtext := make([]byte, hs.KEM().CiphertextSize())
	hs.KEM().Encapsulate(shared, kemCtext, pub, seed)
	return append(out, kemCtext...)
}

func (hs *HandshakeState[XOF, KEMPriv, KEMPub]) kemDecap(priv *KEMPriv, ctext []byte) ([32]byte, error) {
	var kemShared kem.Secret256
	err := hs.KEM().Decapsulate(&kemShared, &hs.kemPriv, ctext)
	return kemShared, err
}

func (hs *HandshakeState[XOF, KEMPriv, KEMPub]) aeadOpen(key *[32]byte, nonce uint64, ctext []byte) ([]byte, error) {
	ptext := make([]byte, 0, len(ctext)-hs.AEAD().Overhead())
	nonceBytes := makeNonce(nonce)
	return aead.AppendOpenK256N64(ptext, hs.AEAD(), key, nonceBytes, ctext, nil)
}

func makeNonce(x uint64) (ret [8]byte) {
	binary.BigEndian.PutUint64(ret[:], x)
	return ret
}

type ErrOOOHandshake struct {
	IsSend bool
	IsInit bool
	Index  uint8
}

func (e ErrOOOHandshake) Error() string {
	return fmt.Sprintf("handshake state machine not expecting message sending=%v init=%v index=%v", e.IsSend, e.IsInit, e.Index)
}

type ErrShortHSMsg struct {
	Index uint8
	Len   int
}

func (e ErrShortHSMsg) Error() string {
	return fmt.Sprintf("message too short (len=%d) to be in handshake (index=%d)", e.Len, e.Index)
}
