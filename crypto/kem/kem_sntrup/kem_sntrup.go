package kem_sntrup

import (
	"errors"
	"fmt"
	"io"

	ntru "github.com/companyzero/sntrup4591761"

	"github.com/brendoncarroll/go-p2p/crypto/kem"
	"github.com/brendoncarroll/go-p2p/crypto/xof"
	"github.com/brendoncarroll/go-p2p/crypto/xof/xof_sha3"
)

type (
	PrivateKey4591761 = ntru.PrivateKey
	PublicKey4591761  = ntru.PublicKey
	Ciphertext4591761 = ntru.Ciphertext
)

const (
	PrivateKey4591761Size = ntru.PrivateKeySize
	PublicKey4591761Size  = ntru.PublicKeySize
	Ciphertext4591761Size = ntru.CiphertextSize
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
	xofScheme := xof_sha3.SHAKE256{}
	rng := xof.NewRand256[xof_sha3.SHAKE256State](xofScheme, seed)
	ct, shared, err := ntru.Encapsulate(&rng, pk)
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
	shared, ec := ntru.Decapsulate((*Ciphertext4591761)(ctext), priv)
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
	return PublicKey4591761Size
}

func (s Scheme4591761) CiphertextSize() int {
	return Ciphertext4591761Size
}

func (s Scheme4591761) PrivateKeySize() int {
	return PrivateKey4591761Size
}

func (s Scheme4591761) MarshalPrivate(dst []byte, priv *PrivateKey4591761) {
	if len(dst) < s.PrivateKeySize() {
		panic(dst)
	}
	copy(dst, priv[:])
}

func (s Scheme4591761) ParsePrivate(x []byte) (PrivateKey4591761, error) {
	if len(x) != s.PrivateKeySize() {
		return PrivateKey4591761{}, errors.New("kem_sntrup: wrong size for private key")
	}
	var ret PrivateKey4591761
	copy(ret[:], x)
	return ret, nil
}
