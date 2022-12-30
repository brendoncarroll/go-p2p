package aead_chacha20poly1305

import (
	"fmt"

	"golang.org/x/crypto/chacha20poly1305"

	"github.com/brendoncarroll/go-p2p/crypto/aead"
)

var (
	_ aead.K256N64  = Scheme{}
	_ aead.K256N192 = Scheme{}
	_ aead.SUV256   = Scheme{}
)

type Scheme struct{}

func (s Scheme) SealK256N64(dst []byte, key *[32]byte, nonce [8]byte, ptext, ad []byte) {
	checkSealDst(dst, ptext)
	aead, err := chacha20poly1305.New(key[:])
	if err != nil {
		panic(err)
	}
	var nonce2 [12]byte
	copy(nonce2[:], nonce[:])
	aead.Seal(dst[:0], nonce2[:], ptext, ad)
}

func (s Scheme) OpenK256N64(dst []byte, key *[32]byte, nonce [8]byte, ctext, ad []byte) error {
	checkOpenDst(dst, ctext)
	aead, err := chacha20poly1305.New(key[:])
	if err != nil {
		panic(err)
	}
	var nonce2 [12]byte
	copy(nonce2[:], nonce[:])
	_, err = aead.Open(dst[:0], nonce2[:], ctext, ad)
	return err
}

func (s Scheme) Overhead() int {
	return chacha20poly1305.Overhead
}

func (s Scheme) SealK256N192(dst []byte, key *[32]byte, nonce *[24]byte, ptext, ad []byte) {
	checkSealDst(dst, ptext)
	aead, err := chacha20poly1305.NewX(key[:])
	if err != nil {
		panic(err)
	}
	aead.Seal(dst[:0], nonce[:], ptext, ad)
}

func (s Scheme) OpenK256N192(dst []byte, key *[32]byte, nonce *[24]byte, ctext, ad []byte) error {
	checkOpenDst(dst, ctext)
	aead, err := chacha20poly1305.NewX(key[:])
	if err != nil {
		panic(err)
	}
	_, err = aead.Open(dst[:0], nonce[:], ctext, ad)
	return err
}

func (s Scheme) SealSUV256(dst []byte, suv *[32]byte, ptext, ad []byte) {
	checkSealDst(dst, ptext)
	aead, err := chacha20poly1305.New(suv[:])
	if err != nil {
		panic(err)
	}
	var nonce [12]byte
	aead.Seal(dst[:0], nonce[:], ptext, ad)
}

func (s Scheme) OpenSUV256(dst []byte, suv *[32]byte, ctext, ad []byte) error {
	checkOpenDst(dst, ctext)
	aead, err := chacha20poly1305.New(suv[:])
	if err != nil {
		panic(err)
	}
	var nonce [12]byte
	_, err = aead.Open(dst[:0], nonce[:], ctext, ad)
	return err
}

func checkSealDst(dst, src []byte) {
	if len(dst) < len(src)+chacha20poly1305.Overhead {
		panic(fmt.Sprintf("dst too short len=%d", len(dst)))
	}
}

func checkOpenDst(dst, src []byte) {
	if len(dst) < len(src)-chacha20poly1305.Overhead {
		panic(fmt.Sprintf("dst too short len=%d", len(dst)))
	}
}
