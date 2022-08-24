package sign

import (
	"io"

	"github.com/pkg/errors"
)

// DualKey is a hybrid key made of 2 keys
type DualKey[A, B any] struct {
	A A
	B B
}

// Dual is a signing scheme composed of two signing schemes
type Dual[APriv, APub, BPriv, BPub any] struct {
	A Scheme[APriv, APub]
	B Scheme[BPriv, BPub]
}

func (s Dual[APriv, APub, BPriv, BPub]) Generate(rng io.Reader) (DualKey[APub, BPub], DualKey[APriv, BPriv], error) {
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

func (s Dual[APriv, APub, BPriv, BPub]) DerivePublic(priv *DualKey[APriv, BPriv]) DualKey[APub, BPub] {
	return DualKey[APub, BPub]{
		A: s.A.DerivePublic(&priv.A),
		B: s.B.DerivePublic(&priv.B),
	}
}

func (s Dual[APriv, APub, BPriv, BPub]) Sign(dst []byte, priv *DualKey[APriv, BPriv], msg []byte) {
	adst := dst[:s.A.SignatureSize()]
	bdst := dst[s.A.SignatureSize():]
	s.A.Sign(adst, &priv.A, msg)
	s.B.Sign(bdst, &priv.B, msg)
}

func (s Dual[APriv, APub, BPriv, BPub]) Verify(pub *DualKey[APub, BPub], msg []byte, sig []byte) bool {
	asig := sig[:s.A.SignatureSize()]
	bsig := sig[s.A.SignatureSize():]
	av := s.A.Verify(&pub.A, msg, asig)
	bv := s.B.Verify(&pub.B, msg, bsig)
	return av && bv
}

func (s Dual[APriv, APub, BPriv, BPub]) MarshalPublic(x DualKey[APub, BPub]) (ret []byte) {
	ret = append(ret, s.A.MarshalPublic(x.A)...)
	ret = append(ret, s.B.MarshalPublic(x.B)...)
	return ret
}

func (s Dual[APriv, APub, BPriv, BPub]) ParsePublic(x []byte) (DualKey[APub, BPub], error) {
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

func (s Dual[APriv, APub, BPriv, BPub]) PublicKeySize() int {
	return s.A.PublicKeySize() + s.B.PublicKeySize()
}

func (s Dual[APriv, APub, BPriv, BPub]) SignatureSize() int {
	return s.A.SignatureSize() + s.B.SignatureSize()
}
