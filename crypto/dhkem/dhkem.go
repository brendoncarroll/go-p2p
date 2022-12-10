// package dhkem implements a Key Encapsulation Mechanism (kem.Scheme) in terms of a Diffie-Hellman Key Exchange (dhke.Scheme)
package dhkem

import (
	"errors"
	"io"

	"golang.org/x/crypto/sha3"

	"github.com/brendoncarroll/go-p2p/crypto/dhke"
	"github.com/brendoncarroll/go-p2p/crypto/kem"
)

var _ kem.Scheme256[struct{}, struct{}] = Scheme256[struct{}, struct{}]{}

type Scheme256[Private, Public any] struct {
	DH dhke.Scheme[Private, Public]
}

func (s Scheme256[Private, Public]) Generate(rng io.Reader) (Public, Private, error) {
	return s.DH.Generate(rng)
}

func (s Scheme256[Private, Public]) DerivePublic(priv *Private) Public {
	return s.DH.DerivePublic(priv)
}

func (s Scheme256[Private, Public]) Encapsulate(ss *kem.Secret256, ctext []byte, pub *Public, seed *kem.Seed) error {
	h := sha3.NewShake256()
	h.Write(seed[:])
	ePub, ePriv, err := s.DH.Generate(h)
	if err != nil {
		return err
	}
	shared := make([]byte, s.DH.SharedSize())
	if err := s.DH.ComputeShared(shared, &ePriv, pub); err != nil {
		return err
	}
	if len(ctext) < s.CiphertextSize() {
		return errors.New("len(dst) < CipherTextSize")
	}
	s.DH.MarshalPublic(ctext, &ePub)
	sha3.ShakeSum256(ss[:], shared)
	return nil
}

func (s Scheme256[Private, Public]) Decapsulate(ss *kem.Secret256, priv *Private, ctext []byte) error {
	ePub, err := s.DH.ParsePublic(ctext)
	if err != nil {
		return err
	}
	shared := make([]byte, s.DH.SharedSize())
	if err := s.DH.ComputeShared(shared, priv, &ePub); err != nil {
		return err
	}
	sha3.ShakeSum256(ss[:], shared)
	return nil
}

func (s Scheme256[Private, Public]) MarshalPublic(dst []byte, x *Public) {
	s.DH.MarshalPublic(dst, x)
}

func (s Scheme256[Private, Public]) ParsePublic(x []byte) (Public, error) {
	return s.DH.ParsePublic(x)
}

func (s Scheme256[Private, Public]) PublicKeySize() int {
	return s.DH.PublicKeySize()
}

func (s Scheme256[Private, Public]) CiphertextSize() int {
	return s.DH.PublicKeySize()
}
