package kem

import (
	"fmt"
	"io"

	"github.com/pkg/errors"
	"golang.org/x/crypto/sha3"
)

// DualKey is a hybrid key made of 2 keys
type DualKey[A, B any] struct {
	A A
	B B
}

type Dual256[APriv, APub, BPriv, BPub any] struct {
	A Scheme256[APriv, APub]
	B Scheme256[BPriv, BPub]
}

func (s Dual256[APriv, APub, BPriv, BPub]) Generate(rng io.Reader) (DualKey[APub, BPub], DualKey[APriv, BPriv], error) {
	pubA, privA, err := s.A.Generate(rng)
	if err != nil {
		return DualKey[APub, BPub]{}, DualKey[APriv, BPriv]{}, err
	}
	pubB, privB, err := s.B.Generate(rng)
	if err != nil {
		return DualKey[APub, BPub]{}, DualKey[APriv, BPriv]{}, err
	}
	return DualKey[APub, BPub]{A: pubA, B: pubB}, DualKey[APriv, BPriv]{A: privA, B: privB}, nil
}

func (s Dual256[APriv, APub, BPriv, BPub]) DerivePublic(x *DualKey[APriv, BPriv]) DualKey[APub, BPub] {
	return DualKey[APub, BPub]{
		A: s.A.DerivePublic(&x.A),
		B: s.B.DerivePublic(&x.B),
	}
}

func (s Dual256[APriv, APub, BPriv, BPub]) Encapsulate(ss *Secret256, ct []byte, pub *DualKey[APub, BPub], seed *Seed) error {
	var seedA, seedB [SeedSize]byte
	sha3.ShakeSum256(seedA[:], append(seed[:], 0))
	sha3.ShakeSum256(seedB[:], append(seed[:], 255))

	var sharedConcat [64]byte
	sharedA := (*[32]byte)(sharedConcat[:32])
	sharedB := (*[32]byte)(sharedConcat[32:])

	s.A.Encapsulate(sharedA, ct[:s.A.CiphertextSize()], &pub.A, &seedA)
	s.B.Encapsulate(sharedB, ct[s.A.CiphertextSize():], &pub.B, &seedB)

	sha3.ShakeSum256(ss[:], sharedConcat[:])
	return nil
}

func (s Dual256[APriv, APub, BPriv, BPub]) Decapsulate(ss *Secret256, priv *DualKey[APriv, BPriv], ct []byte) error {
	var sharedConcat [2 * 32]byte
	sharedA := (*[32]byte)(sharedConcat[:32])
	sharedB := (*[32]byte)(sharedConcat[32:])

	s.A.Decapsulate(sharedA, &priv.A, ct[:s.A.CiphertextSize()])
	s.B.Decapsulate(sharedB, &priv.B, ct[s.A.CiphertextSize():])

	sha3.ShakeSum256(ss[:], sharedConcat[:])
	return nil
}

func (s Dual256[APriv, APub, BPriv, BPub]) MarshalPublic(dst []byte, x *DualKey[APub, BPub]) {
	if len(dst) < s.PublicKeySize() {
		panic(fmt.Sprintf("len(dst) < %d", s.PublicKeySize()))
	}
	s.A.MarshalPublic(dst[:s.A.PublicKeySize()], &x.A)
	s.B.MarshalPublic(dst[s.A.PublicKeySize():], &x.B)
}

func (s Dual256[APriv, APub, BPriv, BPub]) ParsePublic(x []byte) (DualKey[APub, BPub], error) {
	if len(x) != s.A.PublicKeySize()+s.B.PublicKeySize() {
		return DualKey[APub, BPub]{}, errors.Errorf("too short to be public key len=%d", len(x))
	}
	aPub, err := s.A.ParsePublic(x[:s.A.PublicKeySize()])
	if err != nil {
		return DualKey[APub, BPub]{}, err
	}
	bPub, err := s.B.ParsePublic(x[s.A.PublicKeySize():])
	if err != nil {
		return DualKey[APub, BPub]{}, err
	}
	return DualKey[APub, BPub]{A: aPub, B: bPub}, nil
}

func (s Dual256[APriv, APub, BPriv, BPub]) PublicKeySize() int {
	return s.A.PublicKeySize() + s.B.PublicKeySize()
}

func (s Dual256[APriv, APub, BPriv, BPub]) CiphertextSize() int {
	return s.A.CiphertextSize() + s.B.CiphertextSize()
}
