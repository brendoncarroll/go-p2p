// package aead_xof implements an AEAD (aead.Scheme256) in terms of an XOF (xof.Scheme)
package aead_xof

import (
	"crypto/subtle"
	"errors"

	"github.com/brendoncarroll/go-p2p/crypto/aead"
	"github.com/brendoncarroll/go-p2p/crypto/xof"
)

var (
	_ aead.SUV256   = Scheme256[struct{}]{}
	_ aead.K256N64  = Scheme256[struct{}]{}
	_ aead.K256N192 = Scheme256[struct{}]{}
)

type Scheme256[S any] struct {
	XOF xof.Scheme[S]
}

func (s Scheme256[S]) SealSUV256(dst []byte, suv *[32]byte, ptext, ad []byte) {
	k1, k2 := s.deriveKeysSUV(suv)
	s.seal(dst, &k1, &k2, ptext, ad)
}

func (s Scheme256[S]) OpenSUV256(dst []byte, suv *[32]byte, src []byte, ad []byte) error {
	k1, k2 := s.deriveKeysSUV(suv)
	return s.open(dst, &k1, &k2, src, ad)
}

func (s Scheme256[S]) SealK256N64(dst []byte, k *[32]byte, nonce [8]byte, ptext, ad []byte) {
	k1, k2 := s.deriveKeysN64(k, nonce)
	s.seal(dst, &k1, &k2, ptext, ad)
}

func (s Scheme256[S]) OpenK256N64(dst []byte, k *[32]byte, nonce [8]byte, src []byte, ad []byte) error {
	k1, k2 := s.deriveKeysN64(k, nonce)
	return s.open(dst, &k1, &k2, src, ad)
}

func (s Scheme256[S]) SealK256N192(dst []byte, k *[32]byte, nonce *[24]byte, ptext, ad []byte) {
	k1, k2 := s.deriveKeysN192(k, nonce)
	s.seal(dst, &k1, &k2, ptext, ad)
}

func (s Scheme256[S]) OpenK256N192(dst []byte, k *[32]byte, nonce *[24]byte, src []byte, ad []byte) error {
	k1, k2 := s.deriveKeysN192(k, nonce)
	return s.open(dst, &k1, &k2, src, ad)
}

func (s Scheme256[S]) Overhead() int {
	return 32
}

func (s Scheme256[S]) seal(dst []byte, k1, k2 *[32]byte, src, ad []byte) {
	ctext := dst[:len(src)]
	mac := dst[len(src) : len(src)+s.Overhead()]
	s.xorKeyStream(ctext, k1, src)
	s.createMAC(mac, k2, ctext, ad)
}

func (s Scheme256[S]) open(dst []byte, k1, k2 *[32]byte, src, ad []byte) error {
	if len(src) < s.Overhead() {
		return errors.New("aead_xof: input too short")
	}
	ctext := src[:len(src)-s.Overhead()]
	mac := src[len(src)-s.Overhead():]

	var correctMAC [32]byte
	s.createMAC(correctMAC[:], k2, ctext, ad)
	if subtle.ConstantTimeCompare(correctMAC[:], mac) != 1 {
		return errors.New("invalid MAC")
	}
	s.xorKeyStream(dst[:len(ctext)], k1, ctext)
	return nil
}

func (s Scheme256[S]) deriveKeysSUV(suv *[32]byte) (k1, k2 [32]byte) {
	x := s.XOF.New()
	s.XOF.Absorb(&x, suv[:])

	x1 := x
	s.XOF.Absorb(&x1, []byte{0})
	s.XOF.Expand(&x1, k1[:])

	x2 := x
	s.XOF.Absorb(&x2, []byte{1})
	s.XOF.Expand(&x2, k2[:])
	return k1, k2
}

func (s Scheme256[S]) deriveKeysN64(k *[32]byte, n [8]byte) (k1, k2 [32]byte) {
	x := s.XOF.New()
	s.XOF.Absorb(&x, k[:])
	s.XOF.Absorb(&x, n[:])

	x1 := x
	s.XOF.Absorb(&x1, []byte{0})
	s.XOF.Expand(&x1, k1[:])

	x2 := x
	s.XOF.Absorb(&x2, []byte{1})
	s.XOF.Expand(&x2, k2[:])

	return k1, k2
}

func (s Scheme256[S]) deriveKeysN192(k *[32]byte, n *[24]byte) (k1, k2 [32]byte) {
	x := s.XOF.New()
	s.XOF.Absorb(&x, k[:])
	s.XOF.Absorb(&x, n[:])

	x1 := x
	s.XOF.Absorb(&x1, []byte{0})
	s.XOF.Expand(&x1, k1[:])

	x2 := x
	s.XOF.Absorb(&x2, []byte{0})
	s.XOF.Expand(&x2, k2[:])

	return k1, k2
}

func (s Scheme256[S]) xorKeyStream(dst []byte, k *[32]byte, src []byte) {
	x := s.XOF.New()
	s.XOF.Absorb(&x, k[:])
	xof.XOROut(s.XOF, &x, dst, src)
}

func (s Scheme256[S]) createMAC(dst []byte, k *[32]byte, input, ad []byte) {
	x := s.XOF.New()
	s.XOF.Absorb(&x, k[:])
	s.XOF.Absorb(&x, input)
	s.XOF.Absorb(&x, ad)

	s.XOF.Expand(&x, dst)
}
