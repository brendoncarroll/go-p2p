package aead_chacha20poly1305

import (
	"fmt"

	"golang.org/x/crypto/chacha20poly1305"

	"github.com/brendoncarroll/go-p2p/crypto/aead"
)

var _ aead.K256N64 = N64{}

// N64 is an AEAD with an 8 byte nonce
type N64 struct{}

func (s N64) SealK256N64(dst []byte, key *[32]byte, nonce [8]byte, ptext, ad []byte) {
	checkSealDst(dst, ptext)
	aead, err := chacha20poly1305.New(key[:])
	if err != nil {
		panic(err)
	}
	var nonce2 [12]byte
	copy(nonce2[:], nonce[:])
	aead.Seal(dst[:0], nonce2[:], ptext, ad)
}

func (s N64) OpenK256N64(dst []byte, key *[32]byte, nonce [8]byte, ctext, ad []byte) error {
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

func (s N64) Overhead() int {
	return chacha20poly1305.Overhead
}

var _ aead.K256N192 = N192{}

// N192 is an AEAD with a 24 byte nonce
type N192 struct{}

func (s N192) SealK256N192(dst []byte, key *[32]byte, nonce *[24]byte, ptext, ad []byte) {
	checkSealDst(dst, ptext)
	aead, err := chacha20poly1305.NewX(key[:])
	if err != nil {
		panic(err)
	}
	aead.Seal(dst[:0], nonce[:], ptext, ad)
}

func (s N192) OpenK256N192(dst []byte, key *[32]byte, nonce *[24]byte, ctext, ad []byte) error {
	checkOpenDst(dst, ctext)
	aead, err := chacha20poly1305.NewX(key[:])
	if err != nil {
		panic(err)
	}
	_, err = aead.Open(dst[:0], nonce[:], ctext, ad)
	return err
}

func (s N192) Overhead() int {
	return chacha20poly1305.Overhead
}

var _ aead.SUV256 = SUV{}

// SUV is an AEAD which takes a Secret and Unique Value instead of a key and nonce.
type SUV struct{}

func (s SUV) SealSUV256(dst []byte, suv *[32]byte, ptext, ad []byte) {
	checkSealDst(dst, ptext)
	aead, err := chacha20poly1305.New(suv[:])
	if err != nil {
		panic(err)
	}
	var nonce [12]byte
	aead.Seal(dst[:0], nonce[:], ptext, ad)
}

func (s SUV) OpenSUV256(dst []byte, suv *[32]byte, ctext, ad []byte) error {
	checkOpenDst(dst, ctext)
	aead, err := chacha20poly1305.New(suv[:])
	if err != nil {
		panic(err)
	}
	var nonce [12]byte
	_, err = aead.Open(dst[:0], nonce[:], ctext, ad)
	return err
}

func (s SUV) Overhead() int {
	return chacha20poly1305.Overhead
}

func checkOpenDst(dst, src []byte) {
	if len(dst) < len(src)-chacha20poly1305.Overhead {
		panic(fmt.Sprintf("dst too short len=%d", len(dst)))
	}
}

func checkSealDst(dst, src []byte) {
	if len(dst) < len(src)+chacha20poly1305.Overhead {
		panic(fmt.Sprintf("dst too short len=%d", len(dst)))
	}
}
