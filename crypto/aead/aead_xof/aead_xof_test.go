package aead_xof_test

import (
	"testing"

	"github.com/brendoncarroll/go-p2p/crypto/aead"
	"github.com/brendoncarroll/go-p2p/crypto/aead/aead_xof"
	"github.com/brendoncarroll/go-p2p/crypto/xof/xof_sha3"
)

func TestScheme256(t *testing.T) {
	s := aead_xof.Scheme256[xof_sha3.SHAKE256State]{XOF: xof_sha3.SHAKE256{}}
	aead.TestSUV256(t, s)
	aead.TestK256N64(t, s)
	aead.TestK256N192(t, s)
}
