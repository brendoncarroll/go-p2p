package xof

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestScheme[S any](t *testing.T, s Scheme[S]) {
	t.Run("NewReset", func(t *testing.T) {
		x := s.New()
		unused := s.New()

		s.Absorb(&x, []byte("input string"))
		s.Reset(&x)

		var expected, actual [64]byte
		s.Expand(&unused, expected[:])
		s.Expand(&x, actual[:])
		require.Equal(t, expected, actual)
	})
}
