package aead

import (
	"golang.org/x/crypto/chacha20poly1305"
)

var _ SchemeK32N8 = ChaChaN8{}

type ChaChaN8 struct{}

func (s ChaChaN8) Seal(out []byte, key *[32]byte, nonce *[8]byte, ptext, ad []byte) []byte {
	aead, err := chacha20poly1305.New(key[:])
	if err != nil {
		panic(err)
	}
	var nonce2 [12]byte
	copy(nonce2[:], nonce[:])
	return aead.Seal(out, nonce2[:], ptext, ad)
}

func (s ChaChaN8) Open(out []byte, key *[32]byte, nonce *[8]byte, ctext, ad []byte) ([]byte, error) {
	aead, err := chacha20poly1305.New(key[:])
	if err != nil {
		panic(err)
	}
	var nonce2 [12]byte
	copy(nonce2[:], nonce[:])
	return aead.Open(out, nonce2[:], ctext, ad)
}

func (s ChaChaN8) Overhead() int {
	return chacha20poly1305.Overhead
}

var _ SchemeK32N24 = ChaChaN24{}

type ChaChaN24 struct{}

func (s ChaChaN24) Seal(out []byte, key *[32]byte, nonce *[24]byte, ptext, ad []byte) []byte {
	aead, err := chacha20poly1305.NewX(key[:])
	if err != nil {
		panic(err)
	}
	return aead.Seal(out, nonce[:], ptext, ad)
}

func (s ChaChaN24) Open(out []byte, key *[32]byte, nonce *[24]byte, ctext, ad []byte) ([]byte, error) {
	aead, err := chacha20poly1305.NewX(key[:])
	if err != nil {
		panic(err)
	}
	return aead.Open(out, nonce[:], ctext, ad)
}

func (s ChaChaN24) Overhead() int {
	return chacha20poly1305.Overhead
}

var _ SchemeSUV32 = ChaChaSUV{}

type ChaChaSUV struct{}

func (s ChaChaSUV) Seal(out []byte, key *[32]byte, ptext, ad []byte) []byte {
	aead, err := chacha20poly1305.New(key[:])
	if err != nil {
		panic(err)
	}
	var nonce [12]byte
	return aead.Seal(out, nonce[:], ptext, ad)
}

func (s ChaChaSUV) Open(out []byte, key *[32]byte, ctext, ad []byte) ([]byte, error) {
	aead, err := chacha20poly1305.New(key[:])
	if err != nil {
		panic(err)
	}
	var nonce [12]byte
	return aead.Open(out, nonce[:], ctext, ad)
}

func (s ChaChaSUV) Overhead() int {
	return chacha20poly1305.Overhead
}
