package sign

import (
	"fmt"
	"io"

	"github.com/pkg/errors"
)

// DualKey is a hybrid key made of 2 keys
type DualKey[L, R any] struct {
	L L
	R R
}

// Dual is a signing scheme composed of two signing schemes
type Dual[LPriv, LPub, RPriv, RPub any] struct {
	L Scheme[LPriv, LPub]
	R Scheme[RPriv, RPub]
}

func (s Dual[LPriv, LPub, RPriv, RPub]) Generate(rng io.Reader) (DualKey[LPub, RPub], DualKey[LPriv, RPriv], error) {
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

func (s Dual[LPriv, LPub, RPriv, RPub]) DerivePublic(priv *DualKey[LPriv, RPriv]) DualKey[LPub, RPub] {
	return DualKey[LPub, RPub]{
		L: s.L.DerivePublic(&priv.L),
		R: s.R.DerivePublic(&priv.R),
	}
}

func (s Dual[LPriv, LPub, RPriv, RPub]) Sign(dst []byte, priv *DualKey[LPriv, RPriv], input []byte) {
	ldst := dst[:s.L.SignatureSize()]
	rdst := dst[s.L.SignatureSize():]
	s.L.Sign(ldst, &priv.L, input)
	s.R.Sign(rdst, &priv.R, input)
}

func (s Dual[LPriv, LPub, RPriv, RPub]) Verify(pub *DualKey[LPub, RPub], input []byte, sig []byte) bool {
	lsig := sig[:s.L.SignatureSize()]
	rsig := sig[s.L.SignatureSize():]
	lv := s.L.Verify(&pub.L, input, lsig)
	rv := s.R.Verify(&pub.R, input, rsig)
	return lv && rv
}

func (s Dual[LPriv, LPub, RPriv, RPub]) SignatureSize() int {
	return s.L.SignatureSize() + s.R.SignatureSize()
}

func (s Dual[LPriv, LPub, RPriv, RPub]) PublicKeySize() int {
	return s.L.PublicKeySize() + s.R.PublicKeySize()
}

func (s Dual[LPriv, LPub, RPriv, RPub]) MarshalPublic(dst []byte, x *DualKey[LPub, RPub]) {
	if len(dst) < s.PublicKeySize() {
		panic(fmt.Sprintf("len(dst) < %d", s.PublicKeySize()))
	}
	s.L.MarshalPublic(dst[:s.L.PublicKeySize()], &x.L)
	s.R.MarshalPublic(dst[s.L.PublicKeySize():], &x.R)
}

func (s Dual[LPriv, LPub, RPriv, RPub]) ParsePublic(x []byte) (DualKey[LPub, RPub], error) {
	if len(x) != s.L.PublicKeySize()+s.R.PublicKeySize() {
		return DualKey[LPub, RPub]{}, errors.Errorf("too short to be public key len=%d", len(x))
	}
	lPub, err := s.L.ParsePublic(x[:s.L.PublicKeySize()])
	if err != nil {
		return DualKey[LPub, RPub]{}, err
	}
	rPub, err := s.R.ParsePublic(x[s.L.PublicKeySize():])
	if err != nil {
		return DualKey[LPub, RPub]{}, err
	}
	return DualKey[LPub, RPub]{L: lPub, R: rPub}, nil
}

func (s Dual[LPriv, LPub, RPriv, RPub]) PrivateKeySize() int {
	return s.L.PrivateKeySize() + s.R.PrivateKeySize()
}

func (s Dual[LPriv, LPub, RPriv, RPub]) MarshalPrivate(dst []byte, x *DualKey[LPriv, RPriv]) {
	if len(dst) < s.PrivateKeySize() {
		panic(fmt.Sprintf("len(dst) < %d", s.PrivateKeySize()))
	}
	s.L.MarshalPrivate(dst[:s.L.PrivateKeySize()], &x.L)
	s.R.MarshalPrivate(dst[s.L.PrivateKeySize():], &x.R)
}

func (s Dual[LPriv, LPub, RPriv, RPub]) ParsePrivate(x []byte) (DualKey[LPriv, RPriv], error) {
	if len(x) != s.L.PrivateKeySize()+s.R.PrivateKeySize() {
		return DualKey[LPriv, RPriv]{}, errors.Errorf("too short to be public key len=%d", len(x))
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
