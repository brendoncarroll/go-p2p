package xof_sha3

import (
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/sha3"

	"github.com/brendoncarroll/go-p2p/crypto/xof"
)

func TestMatchesStandard(t *testing.T) {
	input := []byte("hello world")
	var expected, actual [64]byte
	sha3.ShakeSum256(expected[:], input)

	s := SHAKE256{}
	xof.Sum[SHAKE256State](s, actual[:], input)

	t.Log("expected", expected, "actual", actual)
	require.Equal(t, expected, actual)
}

func TestSHAKE256(t *testing.T) {
	xof.TestScheme[SHAKE256State](t, SHAKE256{})
}
