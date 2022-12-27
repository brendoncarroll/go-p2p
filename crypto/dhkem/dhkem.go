// package dhkem implements a Key Encapsulation Mechanism (kem.Scheme256) in terms of a Diffie-Hellman Key Exchange (dhke.Scheme)
package dhkem

import (
	"errors"
	"io"

	"github.com/brendoncarroll/go-p2p/crypto/dhke"
	"github.com/brendoncarroll/go-p2p/crypto/kem"
	"github.com/brendoncarroll/go-p2p/crypto/xof"
)

var _ kem.Scheme256[struct{}, struct{}] = Scheme256[struct{}, struct{}, struct{}]{}

type Scheme256[Private, Public, XOF any] struct {
	DH  dhke.Scheme[Private, Public]
	XOF xof.Scheme[XOF]
}

func (s Scheme256[Private, Public, XOF]) Generate(rng io.Reader) (Public, Private, error) {
	return s.DH.Generate(rng)
}

func (s Scheme256[Private, Public, XOF]) DerivePublic(priv *Private) Public {
	return s.DH.DerivePublic(priv)
}

func (s Scheme256[Private, Public, XOF]) Encapsulate(ss *kem.Secret256, ctext []byte, pub *Public, seed *kem.Seed) error {
	rng := xof.NewRand256[XOF](s.XOF, seed)
	ePub, ePriv, err := s.DH.Generate(&rng)
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
	xof.Sum[XOF](s.XOF, ss[:], shared)
	return nil
}

func (s Scheme256[Private, Public, XOF]) Decapsulate(ss *kem.Secret256, priv *Private, ctext []byte) error {
	ePub, err := s.DH.ParsePublic(ctext)
	if err != nil {
		return err
	}
	shared := make([]byte, s.DH.SharedSize())
	if err := s.DH.ComputeShared(shared, priv, &ePub); err != nil {
		return err
	}
	xof.Sum[XOF](s.XOF, ss[:], shared)
	return nil
}

func (s Scheme256[Private, Public, XOF]) MarshalPublic(dst []byte, x *Public) {
	s.DH.MarshalPublic(dst, x)
}

func (s Scheme256[Private, Public, XOF]) ParsePublic(x []byte) (Public, error) {
	return s.DH.ParsePublic(x)
}

func (s Scheme256[Private, Public, XOF]) PublicKeySize() int {
	return s.DH.PublicKeySize()
}

func (s Scheme256[Private, Public, XOF]) CiphertextSize() int {
	return s.DH.PublicKeySize()
}

func (s Scheme256[Private, Public, XOF]) PrivateKeySize() int {
	return s.DH.PrivateKeySize()
}

func (s Scheme256[Private, Public, XOF]) MarshalPrivate(dst []byte, priv *Private) {
	s.DH.MarshalPrivate(dst, priv)
}

func (s Scheme256[Private, Public, XOF]) ParsePrivate(x []byte) (Private, error) {
	return s.DH.ParsePrivate(x)
}
