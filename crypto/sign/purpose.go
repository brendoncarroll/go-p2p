package sign

import (
	"io"

	"golang.org/x/crypto/sha3"
)

// Purpose allows keys to sign with multiple contexts
type Purpose[Private, Public any] struct {
	Scheme[Private, Public]
	Purpose string
}

func NewPurpose[Private, Public any](s Scheme[Private, Public], purpose string) Purpose[Private, Public] {
	return Purpose[Private, Public]{Scheme: s, Purpose: purpose}
}

func (s Purpose[Private, Public]) Sign(dst []byte, priv *Private, msg []byte) {
	var msg2 [64]byte
	xof := makeXOF(s.Purpose, msg)
	if _, err := io.ReadFull(xof, msg2[:]); err != nil {
		panic(err)
	}
	s.Scheme.Sign(dst, priv, msg2[:])
}

func (s Purpose[Private, Public]) Verify(pub *Public, sig, msg []byte) bool {
	var msg2 [64]byte
	xof := makeXOF(s.Purpose, msg)
	if _, err := io.ReadFull(xof, msg2[:]); err != nil {
		panic(err)
	}
	return s.Scheme.Verify(pub, sig, msg2[:])
}

func makeXOF(purpose string, data []byte) sha3.ShakeHash {
	xof := sha3.NewCShake256(nil, []byte(purpose))
	if _, err := xof.Write([]byte(data)); err != nil {
		panic(err)
	}
	return xof
}
