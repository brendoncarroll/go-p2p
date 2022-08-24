// package dhkem implements a Key Encapsulation Mechanism (kem.Scheme) in terms of a Diffie-Hellman Key Exchange (dhke.Scheme)
package dhkem

import (
	"io"

	"github.com/brendoncarroll/go-p2p/crypto/dhke"
	"github.com/brendoncarroll/go-p2p/crypto/kem"
	"golang.org/x/crypto/sha3"
)

var _ kem.Scheme[struct{}, struct{}] = Scheme[struct{}, struct{}]{}

type Scheme[Private, Public any] struct {
	DH dhke.Scheme[Private, Public]
}

func (s Scheme[Private, Public]) Generate(rng io.Reader) (Public, Private, error) {
	return s.DH.Generate(rng)
}

func (s Scheme[Private, Public]) DerivePublic(priv *Private) Public {
	return s.DH.DerivePublic(priv)
}

func (s Scheme[Private, Public]) Encapsulate(ss *kem.SharedSecret, ctext []byte, pub *Public, seed *kem.Seed) error {
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
	copy(ctext, s.DH.MarshalPublic(ePub))
	sha3.ShakeSum256(ss[:], shared)
	return nil
}

func (s Scheme[Private, Public]) Decapsulate(ss *kem.SharedSecret, priv *Private, ctext []byte) error {
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

func (s Scheme[Private, Public]) MarshalPublic(x Public) []byte {
	return s.DH.MarshalPublic(x)
}

func (s Scheme[Private, Public]) ParsePublic(x []byte) (Public, error) {
	return s.DH.ParsePublic(x)
}

func (s Scheme[Private, Public]) PublicKeySize() int {
	return s.DH.PublicKeySize()
}

func (s Scheme[Private, Public]) CiphertextSize() int {
	return s.DH.PublicKeySize()
}
