package oids

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestEqual(t *testing.T) {
	require.Equal(t, New(), New())
	require.NotEqual(t, New(), New(1))
	require.Equal(t, New(0), New(0))
	require.NotEqual(t, New(0), New(1))
	require.Equal(t, New(1, 2, 3), New(1, 2, 3))
}
