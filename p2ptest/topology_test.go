package p2ptest

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestTopology(t *testing.T) {
	t.Run("TestChain", func(t *testing.T) {
		for i := 0; i < 20; i++ {
			testAdjList(t, i, Chain(i))
		}
	})
	t.Run("TestRing", func(t *testing.T) {
		for i := 0; i < 20; i++ {
			testAdjList(t, i, Ring(i))
		}
	})
	t.Run("TestCluster", func(t *testing.T) {
		for i := 0; i < 20; i++ {
			testAdjList(t, i, Cluster(i))
		}
	})
	t.Run("TestHubAndSpoke", func(t *testing.T) {
		for i := 0; i < 20; i++ {
			testAdjList(t, i, HubAndSpoke(i))
		}
	})
}

func testAdjList(t *testing.T, n int, x AdjList) {
	require.Len(t, x, n)
	for i := range x {
		for _, j := range x[i] {
			// not out of bounds
			require.Less(t, j, n)
			require.GreaterOrEqual(t, j, 0)

			// not self reference
			require.NotEqual(t, i, j)
		}
	}
}
