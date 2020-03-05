package cellutil

import (
	"context"
	"fmt"
	"testing"

	"github.com/brendoncarroll/go-p2p"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type Cell = p2p.Cell

func CellTestSuite(t *testing.T, factory func() Cell) {
	c := factory()
	ctx := context.TODO()

	data, err := c.Get(ctx)
	require.Nil(t, err)
	assert.Len(t, data, 0)

	const N = 10
	current := data
	for i := 0; i < N; i++ {
		next := []byte(fmt.Sprint("test data ", i))
		success, _, err := c.CAS(ctx, current, next)
		require.Nil(t, err)
		require.True(t, success)
		current = next
	}
}
