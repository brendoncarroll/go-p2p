package cryptocell

import (
	"testing"

	"github.com/brendoncarroll/go-p2p/p2ptest"
	"github.com/brendoncarroll/go-state/cells"
	"github.com/brendoncarroll/go-state/cells/celltest"
	"github.com/stretchr/testify/require"
)

const defaultSize = 1 << 16

func TestSigned(t *testing.T) {
	celltest.CellTestSuite(t, func(t testing.TB) cells.Cell {
		return newTestSigned(t)
	})
}

func newTestSigned(t testing.TB) *Signed {
	key1 := p2ptest.NewTestKey(t, 0)
	return NewSigned(cells.NewMem(defaultSize), "signed-cell", key1.Public(), key1)
}

func TestSigWrapUnwrap(t *testing.T) {
	s := newTestSigned(t)
	buf := make([]byte, s.MaxSize())

	testInput := []byte("test input string 1")
	n, err := s.wrap(buf, testInput)
	require.NoError(t, err)
	require.Equal(t, overhead+len(testInput), n)

	_, err = s.unwrap(buf, buf[:n])
	require.NoError(t, err)
}
