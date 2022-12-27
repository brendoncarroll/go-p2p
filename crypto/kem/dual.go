package kem

import (
	"fmt"
	"io"

	"github.com/pkg/errors"

	"github.com/brendoncarroll/go-p2p/crypto/xof"
)

// DualKey is a hybrid key made of 2 keys
type DualKey[L, R any] struct {
	L L
	R R
}

type Dual256[LPriv, LPub, RPriv, RPub, XOF any] struct {
	L   Scheme256[LPriv, LPub]
	R   Scheme256[RPriv, RPub]
	XOF xof.Scheme[XOF]
}

func (s Dual256[LPriv, LPub, RPriv, RPub, XOF]) Generate(rng io.Reader) (DualKey[LPub, RPub], DualKey[LPriv, RPriv], error) {
	pubL, privL, err := s.L.Generate(rng)
	if err != nil {
		return DualKey[LPub, RPub]{}, DualKey[LPriv, RPriv]{}, err
	}
	pubR, privR, err := s.R.Generate(rng)
	if err != nil {
		return DualKey[LPub, RPub]{}, DualKey[LPriv, RPriv]{}, err
	}
	return DualKey[LPub, RPub]{L: pubL, R: pubR}, DualKey[LPriv, RPriv]{L: privL, R: privR}, nil
}

func (s Dual256[LPriv, LPub, RPriv, RPub, XOF]) DerivePublic(x *DualKey[LPriv, RPriv]) DualKey[LPub, RPub] {
	return DualKey[LPub, RPub]{
		L: s.L.DerivePublic(&x.L),
		R: s.R.DerivePublic(&x.R),
	}
}

func (s Dual256[LPriv, LPub, RPriv, RPub, XOF]) Encapsulate(ss *Secret256, ct []byte, pub *DualKey[LPub, RPub], seed *Seed) error {
	var seedL, seedR [SeedSize]byte
	xof.DeriveKey256[XOF](s.XOF, seedL[:], seed, []byte{0})
	xof.DeriveKey256[XOF](s.XOF, seedR[:], seed, []byte{255})

	var sharedConcat [64]byte
	sharedL := (*[32]byte)(sharedConcat[:32])
	sharedR := (*[32]byte)(sharedConcat[32:])

	s.L.Encapsulate(sharedL, ct[:s.L.CiphertextSize()], &pub.L, &seedL)
	s.R.Encapsulate(sharedR, ct[s.L.CiphertextSize():], &pub.R, &seedR)

	xof.Sum[XOF](s.XOF, ss[:], sharedConcat[:])
	return nil
}

func (s Dual256[LPriv, LPub, RPriv, RPub, XOF]) Decapsulate(ss *Secret256, priv *DualKey[LPriv, RPriv], ct []byte) error {
	var sharedConcat [2 * 32]byte
	sharedL := (*[32]byte)(sharedConcat[:32])
	sharedR := (*[32]byte)(sharedConcat[32:])

	s.L.Decapsulate(sharedL, &priv.L, ct[:s.L.CiphertextSize()])
	s.R.Decapsulate(sharedR, &priv.R, ct[s.L.CiphertextSize():])

	xof.Sum[XOF](s.XOF, ss[:], sharedConcat[:])
	return nil
}

func (s Dual256[LPriv, LPub, RPriv, RPub, XOF]) MarshalPublic(dst []byte, x *DualKey[LPub, RPub]) {
	if len(dst) < s.PublicKeySize() {
		panic(fmt.Sprintf("len(dst) < %d", s.PublicKeySize()))
	}
	s.L.MarshalPublic(dst[:s.L.PublicKeySize()], &x.L)
	s.R.MarshalPublic(dst[s.L.PublicKeySize():], &x.R)
}

func (s Dual256[LPriv, LPub, RPriv, RPub, XOF]) ParsePublic(x []byte) (DualKey[LPub, RPub], error) {
	if len(x) != s.L.PublicKeySize()+s.R.PublicKeySize() {
		return DualKey[LPub, RPub]{}, errors.Errorf("too short to be public key len=%d", len(x))
	}
	aPub, err := s.L.ParsePublic(x[:s.L.PublicKeySize()])
	if err != nil {
		return DualKey[LPub, RPub]{}, err
	}
	bPub, err := s.R.ParsePublic(x[s.L.PublicKeySize():])
	if err != nil {
		return DualKey[LPub, RPub]{}, err
	}
	return DualKey[LPub, RPub]{L: aPub, R: bPub}, nil
}

func (s Dual256[LPriv, LPub, RPriv, RPub, XOF]) PublicKeySize() int {
	return s.L.PublicKeySize() + s.R.PublicKeySize()
}

func (s Dual256[LPriv, LPub, RPriv, RPub, XOF]) CiphertextSize() int {
	return s.L.CiphertextSize() + s.R.CiphertextSize()
}

func (s Dual256[LPriv, LPub, RPriv, RPub, XOF]) PrivateKeySize() int {
	return s.L.PrivateKeySize() + s.R.PrivateKeySize()
}

func (s Dual256[LPriv, LPub, RPriv, RPub, XOF]) MarshalPrivate(dst []byte, x *DualKey[LPriv, RPriv]) {
	s.L.MarshalPrivate(dst[:s.L.PublicKeySize()], &x.L)
	s.R.MarshalPrivate(dst[s.L.PublicKeySize():], &x.R)
}

func (s Dual256[LPriv, LPub, RPriv, RPub, XOF]) ParsePrivate(x []byte) (DualKey[LPriv, RPriv], error) {
	if len(x) != s.L.PrivateKeySize()+s.R.PrivateKeySize() {
		return DualKey[LPriv, RPriv]{}, errors.Errorf("too short to be private key len=%d", len(x))
	}
	lPriv, err := s.L.ParsePrivate(x[:s.L.PrivateKeySize()])
	if err != nil {
		return DualKey[LPriv, RPriv]{}, err
	}
	rPriv, err := s.R.ParsePrivate(x[s.L.PrivateKeySize():])
	if err != nil {
		return DualKey[LPriv, RPriv]{}, err
	}
	return DualKey[LPriv, RPriv]{L: lPriv, R: rPriv}, nil
}
