package aead_chacha20poly1305

import (
	"github.com/brendoncarroll/go-p2p/crypto/aead"
	"testing"
)

func TestN64(t *testing.T) {
	s := Scheme{}
	aead.TestK256N64(t, s)
}

func TestN192(t *testing.T) {
	s := Scheme{}
	aead.TestK256N192(t, s)
}

func TestSUV(t *testing.T) {
	s := Scheme{}
	aead.TestSUV256(t, s)
}
