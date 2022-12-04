package signedcell

import (
	"context"
	"crypto/rand"
	"testing"

	"github.com/brendoncarroll/go-state/cells"
	"github.com/brendoncarroll/go-state/cells/celltest"
	"github.com/stretchr/testify/require"

	"github.com/brendoncarroll/go-p2p/crypto/sign/sig_ed25519"
)

var ctx = context.Background()

const defaultSize = 1 << 16

func TestSigned(t *testing.T) {
	celltest.CellTestSuite(t, func(t testing.TB) cells.Cell {
		return newTestCell(t)
	})
}

func newTestCell(t testing.TB) *Cell[sig_ed25519.PrivateKey, sig_ed25519.PublicKey] {
	s := sig_ed25519.Ed25519{}
	pub, priv, err := s.Generate(rand.Reader)
	require.NoError(t, err)
	return New[sig_ed25519.PrivateKey, sig_ed25519.PublicKey](cells.NewMem(defaultSize), s, &priv, []sig_ed25519.PublicKey{pub})
}

func TestSigWrapUnwrap(t *testing.T) {
	s := newTestCell(t)
	buf := make([]byte, s.MaxSize())

	testInput := []byte("test input string 1")
	n := s.wrap(buf, testInput)
	require.Equal(t, s.Overhead()+len(testInput), n)

	_, err := s.unwrap(buf, buf[:n])
	require.NoError(t, err)
}

func TestWriteRead(t *testing.T) {
	c := newTestCell(t)
	buf := make([]byte, c.MaxSize())

	testInput := "test input string 1"
	swapped, _, err := c.CAS(ctx, buf, nil, []byte(testInput))
	require.NoError(t, err)
	require.True(t, swapped)

	buf2 := make([]byte, c.MaxSize())
	n, err := c.Read(ctx, buf2)
	require.NoError(t, err)
	require.Equal(t, testInput, string(buf2[:n]))
}
