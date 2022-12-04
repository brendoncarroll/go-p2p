package aead_chacha20poly1305

import (
	"golang.org/x/crypto/chacha20poly1305"

	"github.com/brendoncarroll/go-p2p/crypto/aead"
)

var _ aead.SchemeK32N8 = N8{}

// N8 is an AEAD with an 8 byte nonce
type N8 struct{}

func (s N8) Seal(out []byte, key *[32]byte, nonce *[8]byte, ptext, ad []byte) []byte {
	aead, err := chacha20poly1305.New(key[:])
	if err != nil {
		panic(err)
	}
	var nonce2 [12]byte
	copy(nonce2[:], nonce[:])
	return aead.Seal(out, nonce2[:], ptext, ad)
}

func (s N8) Open(out []byte, key *[32]byte, nonce *[8]byte, ctext, ad []byte) ([]byte, error) {
	aead, err := chacha20poly1305.New(key[:])
	if err != nil {
		panic(err)
	}
	var nonce2 [12]byte
	copy(nonce2[:], nonce[:])
	return aead.Open(out, nonce2[:], ctext, ad)
}

func (s N8) Overhead() int {
	return chacha20poly1305.Overhead
}

var _ aead.SchemeK32N24 = N24{}

// N24 is an AEAD with a 24 byte nonce
type N24 struct{}

func (s N24) Seal(out []byte, key *[32]byte, nonce *[24]byte, ptext, ad []byte) []byte {
	aead, err := chacha20poly1305.NewX(key[:])
	if err != nil {
		panic(err)
	}
	return aead.Seal(out, nonce[:], ptext, ad)
}

func (s N24) Open(out []byte, key *[32]byte, nonce *[24]byte, ctext, ad []byte) ([]byte, error) {
	aead, err := chacha20poly1305.NewX(key[:])
	if err != nil {
		panic(err)
	}
	return aead.Open(out, nonce[:], ctext, ad)
}

func (s N24) Overhead() int {
	return chacha20poly1305.Overhead
}

var _ aead.SchemeSUV32 = SUV{}

// SUV is an AEAD which takes a Secret and Unique Value instead of a key and nonce.
type SUV struct{}

func (s SUV) Seal(out []byte, suv *[32]byte, ptext, ad []byte) []byte {
	aead, err := chacha20poly1305.New(suv[:])
	if err != nil {
		panic(err)
	}
	var nonce [12]byte
	return aead.Seal(out, nonce[:], ptext, ad)
}

func (s SUV) Open(out []byte, suv *[32]byte, ctext, ad []byte) ([]byte, error) {
	aead, err := chacha20poly1305.New(suv[:])
	if err != nil {
		panic(err)
	}
	var nonce [12]byte
	return aead.Open(out, nonce[:], ctext, ad)
}

func (s SUV) Overhead() int {
	return chacha20poly1305.Overhead
}
