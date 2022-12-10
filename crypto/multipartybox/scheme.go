package multipartybox

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/sha3"

	"github.com/brendoncarroll/go-p2p/crypto/aead"
	"github.com/brendoncarroll/go-p2p/crypto/kem"
	"github.com/brendoncarroll/go-p2p/crypto/sign"
)

type PrivateKey[KEMPriv, SigPriv any] struct {
	KEM  KEMPriv
	Sign SigPriv
}

type PublicKey[KEMPub, SigPub any] struct {
	KEM  KEMPub
	Sign SigPub
}

type Scheme[KEMPriv, KEMPub, SigPriv, SigPub any] struct {
	KEM  kem.Scheme256[KEMPriv, KEMPub]
	Sign sign.Scheme[SigPriv, SigPub]
	AEAD aead.SchemeSUV256
}

func (s *Scheme[KEMPriv, KEMPub, SigPriv, SigPub]) Generate(rng io.Reader) (retPub PublicKey[KEMPub, SigPub], retPriv PrivateKey[KEMPriv, SigPriv], _ error) {
	kemPub, kemPriv, err := s.KEM.Generate(rng)
	if err != nil {
		return retPub, retPriv, err
	}
	signPub, signPriv, err := s.Sign.Generate(rng)
	if err != nil {
		return retPub, retPriv, err
	}
	retPub = PublicKey[KEMPub, SigPub]{KEM: kemPub, Sign: signPub}
	retPriv = PrivateKey[KEMPriv, SigPriv]{KEM: kemPriv, Sign: signPriv}
	return retPub, retPriv, nil
}

func (s *Scheme[KEMPriv, KEMPub, SigPriv, SigPub]) DerivePublic(priv PrivateKey[KEMPriv, SigPriv]) PublicKey[KEMPub, SigPub] {
	return PublicKey[KEMPub, SigPub]{
		KEM:  s.KEM.DerivePublic(&priv.KEM),
		Sign: s.Sign.DerivePublic(&priv.Sign),
	}
}

func (s *Scheme[KEMPriv, KEMPub, SigPriv, SigPub]) MarshalPublic(dst []byte, pub *PublicKey[KEMPub, SigPub]) {
	s.KEM.MarshalPublic(dst[:s.KEM.PublicKeySize()], &pub.KEM)
	s.Sign.MarshalPublic(dst[s.KEM.PublicKeySize():], &pub.Sign)
}

func (s *Scheme[KEMPriv, KEMPub, SigPriv, SigPub]) ParsePublic(x []byte) (ret PublicKey[KEMPub, SigPub], _ error) {
	kemPub, err := s.KEM.ParsePublic(x[:s.KEM.PublicKeySize()])
	if err != nil {
		return ret, err
	}
	sigPub, err := s.Sign.ParsePublic(x[s.KEM.PublicKeySize():])
	if err != nil {
		return ret, err
	}
	return PublicKey[KEMPub, SigPub]{KEM: kemPub, Sign: sigPub}, nil
}

func (s *Scheme[KEMPriv, KEMPub, SigPriv, SigPub]) Encrypt(out []byte, private *PrivateKey[KEMPriv, SigPriv], pubs []KEMPub, seed *[32]byte, ptext []byte) ([]byte, error) {
	out = appendVarint(out, uint64(s.slotSize()*len(pubs)))
	slotsBegin := len(out)
	var dek, kemSeed [32]byte
	shakeDeriveKey(dek[:], seed, "dek")
	shakeDeriveKey(kemSeed[:], seed, "kem")
	for _, pub := range pubs {
		var err error
		out, err = s.encryptSlot(out, private, &pub, &kemSeed, &dek)
		if err != nil {
			return nil, err
		}
	}
	slotsEnd := len(out)
	out = appendVarint(out, uint64(len(ptext)+s.AEAD.Overhead()))
	out = s.AEAD.Seal(out, &dek, ptext, out[slotsBegin:slotsEnd])
	return out, nil
}

func (s *Scheme[KEMPriv, KEMPub, SigPriv, SigPub]) EncryptDet(out []byte, private *PrivateKey[KEMPriv, SigPriv], pubs []KEMPub, ptext []byte) ([]byte, error) {
	var seed [32]byte
	sha3.ShakeSum256(seed[:], ptext)
	return s.Encrypt(out, private, pubs, &seed, ptext)
}

func (s *Scheme[KEMPriv, KEMPub, SigPriv, SigPub]) Decrypt(out []byte, private *PrivateKey[KEMPriv, SigPriv], writers []SigPub, ctext []byte) (int, []byte, error) {
	m, err := ParseMessage(ctext)
	if err != nil {
		return -1, nil, err
	}
	if len(m.Slots)%s.slotSize() != 0 {
		return -1, nil, fmt.Errorf("incorrect slot size")
	}
	numSlots := len(m.Slots) / s.slotSize()
	for i := 0; i < numSlots; i++ {
		begin := i * s.slotSize()
		end := (i + 1) * s.slotSize()
		sender, dek, err := s.decryptSlot(private, writers, m.Slots[begin:end])
		if err != nil {
			continue
		}
		ptex, err := s.AEAD.Open(out, dek, m.Main, m.Slots)
		return sender, ptex, err
	}
	return -1, nil, errors.New("could not decrypt message")
}

func (s *Scheme[KEMPriv, KEMPub, SigPriv, SigPub]) encryptSlot(out []byte, private *PrivateKey[KEMPriv, SigPriv], pub *KEMPub, seed, dek *[32]byte) ([]byte, error) {
	var ss [32]byte
	kemct := make([]byte, s.KEM.CiphertextSize())
	if err := s.KEM.Encapsulate(&ss, kemct, pub, seed); err != nil {
		return nil, err
	}
	out = append(out, kemct...)

	ptext := make([]byte, s.Sign.SignatureSize()+32)
	s.Sign.Sign(ptext[:s.Sign.SignatureSize()], &private.Sign, kemct[:])
	copy(ptext[s.Sign.SignatureSize():], dek[:])
	out = s.AEAD.Seal(out, &ss, ptext[:], kemct)
	return out, nil
}

// decryptSlot attempts to use private to recover a shared secret from the KEM ciphertext.
// if it is successful, the remaining message is interpretted as a sealed AEAD ciphertext, containing a signature and the main DEK.
func (s *Scheme[KEMPriv, KEMPub, SigPriv, SigPub]) decryptSlot(private *PrivateKey[KEMPriv, SigPriv], pubs []SigPub, ctext []byte) (int, *[32]byte, error) {
	kemCtext := ctext[:s.KEM.CiphertextSize()]
	aeadCtext := ctext[s.KEM.CiphertextSize():]
	var ss [32]byte
	if err := s.KEM.Decapsulate(&ss, &private.KEM, kemCtext); err != nil {
		return -1, nil, err
	}
	ptext, err := s.AEAD.Open(nil, &ss, aeadCtext, kemCtext)
	if err != nil {
		return -1, nil, err
	}
	sig := ptext[:s.Sign.SignatureSize()]
	for i, pub := range pubs {
		if s.Sign.Verify(&pub, kemCtext, sig) {
			dek := ptext[s.Sign.SignatureSize():]
			if len(dek) != 32 {
				return -1, nil, errors.New("DEK is wrong length")
			}
			return i, (*[32]byte)(dek), nil
		}
	}
	return -1, nil, errors.New("could not authenticate slot")
}

func (s *Scheme[KEMPriv, KEMPub, SigPriv, SigPub]) slotSize() int {
	const AEADKeySize = 32
	return s.KEM.CiphertextSize() + s.Sign.SignatureSize() + AEADKeySize + s.AEAD.Overhead()
}

func (s *Scheme[KEMPriv, KEMPub, SigPriv, SigPub]) CiphertextSize(numParties, ptextLen int) int {
	slotsLen := numParties * s.slotSize()
	mainLen := ptextLen + s.AEAD.Overhead()
	return lpLen(slotsLen) + lpLen(mainLen)
}

func (s *Scheme[KEMPriv, KEMPub, SigPriv, SigPub]) PlaintextSize(ctext []byte) (int, error) {
	m, err := ParseMessage(ctext)
	if err != nil {
		return 0, err
	}
	return len(m.Main) - s.AEAD.Overhead(), nil
}

type Message struct {
	Slots []byte
	Main  []byte
}

func ParseMessage(x []byte) (*Message, error) {
	l, n := binary.Uvarint(x)
	if n <= 0 {
		return nil, errors.New("error parsing varint")
	}
	start := n
	end := start + int(l)
	if end > len(x) {
		return nil, fmt.Errorf("varint points out of bounds")
	}
	slots := x[start:end]
	l2, n2 := binary.Uvarint(x[end:])
	if n2 <= 0 {
		return nil, errors.New("error parsing varint")
	}
	start = end + n2
	end = start + int(l2)
	if start >= len(x) || end > len(x) {
		return nil, fmt.Errorf("varint points out of bounds")
	}
	main := x[start:end]
	return &Message{
		Slots: slots,
		Main:  main,
	}, nil
}

func lpLen(x int) int {
	buf := [binary.MaxVarintLen64]byte{}
	l := binary.PutUvarint(buf[:], uint64(x))
	return x + l
}

func appendVarint(out []byte, x uint64) []byte {
	buf := [binary.MaxVarintLen64]byte{}
	l := binary.PutUvarint(buf[:], x)
	return append(out, buf[:l]...)
}

func shakeDeriveKey(dst []byte, seed *[32]byte, purpose string) {
	var input []byte
	input = append(input, seed[:]...)
	input = append(input, purpose...)
	sha3.ShakeSum256(dst, input)
}
