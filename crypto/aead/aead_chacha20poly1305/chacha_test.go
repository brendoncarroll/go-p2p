package aead_chacha20poly1305

import (
	"github.com/brendoncarroll/go-p2p/crypto/aead"
	"testing"
)

func TestN8(t *testing.T) {
	s := N8{}
	aead.TestSchemeK32N8(t, s)
}

func TestN24(t *testing.T) {
	s := N24{}
	aead.TestSchemeK32N24(t, s)
}

func TestSUV(t *testing.T) {
	s := SUV{}
	aead.TestSchemeSUV32(t, s)
}
