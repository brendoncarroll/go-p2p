package kem_sntrup

import (
	"errors"
	"fmt"
	"io"

	ntru "github.com/companyzero/sntrup4591761"
	"golang.org/x/crypto/sha3"

	"github.com/brendoncarroll/go-p2p/crypto/kem"
)

type (
	PrivateKey4591761 = ntru.PrivateKey
	PublicKey4591761  = ntru.PublicKey
)

var _ kem.Scheme256[PrivateKey4591761, PublicKey4591761] = Scheme4591761{}

type Scheme4591761 struct{}

func New4591761() Scheme4591761 {
	return Scheme4591761{}
}

func (s Scheme4591761) Generate(rng io.Reader) (PublicKey4591761, PrivateKey4591761, error) {
	pub, priv, err := ntru.GenerateKey(rng)
	if err != nil {
		return PublicKey4591761{}, PrivateKey4591761{}, err
	}
	return *pub, *priv, nil
}

func (s Scheme4591761) DerivePublic(priv *PrivateKey4591761) (pub PublicKey4591761) {
	copy(pub[:], priv[382:])
	return pub
}

func (s Scheme4591761) Encapsulate(ss *kem.Secret256, ctext []byte, pk *PublicKey4591761, seed *kem.Seed) error {
	h := sha3.NewShake256()
	h.Write(seed[:])
	ct, shared, err := ntru.Encapsulate(h, pk)
	if err != nil {
		return err
	}
	if len(ctext) != len(ct) {
		panic(len(ctext))
	}
	copy(ctext, ct[:])
	copy(ss[:], shared[:])
	return nil
}

func (s Scheme4591761) Decapsulate(ss *kem.Secret256, priv *PrivateKey4591761, ctext []byte) error {
	shared, ec := ntru.Decapsulate((*ntru.Ciphertext)(ctext), priv)
	if ec == 0 {
		return errors.New("ciphertext is invalid")
	}
	copy(ss[:], shared[:])
	return nil
}

func (s Scheme4591761) MarshalPublic(dst []byte, x *PublicKey4591761) {
	if len(dst) < s.PublicKeySize() {
		panic(fmt.Sprintf("len(dst) < %d", s.PublicKeySize()))
	}
	copy(dst, x[:])
}

func (s Scheme4591761) ParsePublic(x []byte) (PublicKey4591761, error) {
	if len(x) != ntru.PublicKeySize {
		return PublicKey4591761{}, fmt.Errorf("wrong size for public key: %d", len(x))
	}
	return *(*PublicKey4591761)(x), nil
}

func (s Scheme4591761) PublicKeySize() int {
	return ntru.PublicKeySize
}

func (s Scheme4591761) CiphertextSize() int {
	return ntru.CiphertextSize
}
