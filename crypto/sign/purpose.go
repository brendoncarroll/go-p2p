package sign

import (
	"io"

	"github.com/brendoncarroll/go-p2p/crypto/xof"
)

var _ Scheme[struct{}, struct{}] = Purpose[struct{}, struct{}, struct{}]{}

// Purpose allows keys to sign with multiple contexts
type Purpose[Private, Public, XOF any] struct {
	Scheme  Scheme512[Private, Public]
	Purpose string
	XOF     xof.Scheme[XOF]
}

func NewPurpose[Private, Public, XOF any](s Scheme512[Private, Public], xofSch xof.Scheme[XOF], purpose string) Purpose[Private, Public, XOF] {
	return Purpose[Private, Public, XOF]{Scheme: s, Purpose: purpose, XOF: xofSch}
}

func (s Purpose[Private, Public, XOF]) Generate(rng io.Reader) (Public, Private, error) {
	return s.Scheme.Generate(rng)
}

func (s Purpose[Private, Public, XOF]) DerivePublic(priv *Private) Public {
	return s.Scheme.DerivePublic(priv)
}

func (s Purpose[Private, Public, XOF]) Sign(dst []byte, priv *Private, msg []byte) {
	input2 := s.makeInput(s.Purpose, msg)
	s.Scheme.Sign512(dst, priv, &input2)
}

func (s Purpose[Private, Public, XOF]) Sign512(dst []byte, priv *Private, input *Input512) {
	s.Sign(dst, priv, input[:])
}

func (s Purpose[Private, Public, XOF]) Verify(pub *Public, msg, sig []byte) bool {
	input2 := s.makeInput(s.Purpose, msg)
	return s.Scheme.Verify512(pub, &input2, sig)
}

func (s Purpose[Private, Public, XOF]) Verify512(pub *Public, input *Input512, sig []byte) bool {
	return s.Verify(pub, input[:], sig)
}

func (s Purpose[Private, Public, XOF]) SignatureSize() int {
	return s.Scheme.SignatureSize()
}

func (s Purpose[Private, Public, XOF]) PublicKeySize() int {
	return s.Scheme.PublicKeySize()
}

func (s Purpose[Private, Public, XOF]) MarshalPublic(dst []byte, pub *Public) {
	s.Scheme.MarshalPublic(dst, pub)
}

func (s Purpose[Private, Public, XOF]) ParsePublic(data []byte) (Public, error) {
	return s.Scheme.ParsePublic(data)
}

func (s Purpose[Private, Public, XOF]) makeInput(purpose string, data []byte) (ret Input512) {
	if len(purpose) > 255 {
		panic(len(purpose))
	}
	x := s.XOF.New()
	s.XOF.Absorb(&x, []byte{uint8(len(purpose))})
	s.XOF.Absorb(&x, []byte(purpose))
	s.XOF.Absorb(&x, data)
	s.XOF.Expand(&x, ret[:])
	return ret
}
