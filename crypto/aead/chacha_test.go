package aead_test

import (
	"github.com/brendoncarroll/go-p2p/crypto/aead"
	"testing"
)

func TestChaCha20Poly1305x8(t *testing.T) {
	s := aead.ChaChaN8{}
	aead.TestSchemeK32N8(t, s)
}

func TestChaCha20Poly1305x24(t *testing.T) {
	s := aead.ChaChaN24{}
	aead.TestSchemeK32N24(t, s)
}
