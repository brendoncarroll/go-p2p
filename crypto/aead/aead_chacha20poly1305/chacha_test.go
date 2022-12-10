package aead_chacha20poly1305

import (
	"github.com/brendoncarroll/go-p2p/crypto/aead"
	"testing"
)

func TestN64(t *testing.T) {
	s := N64{}
	aead.TestSchemeK32N8(t, s)
}

func TestN192(t *testing.T) {
	s := N192{}
	aead.TestSchemeK256N192(t, s)
}

func TestSUV(t *testing.T) {
	s := SUV{}
	aead.TestSchemeSUV256(t, s)
}
