package kademlia

import (
	mrand "math/rand"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCacheClosest(t *testing.T) {
	locus := []byte{1, 1, 1}
	c := NewCache[string](locus, 10, 0)

	c.Put([]byte{3, 3, 3}, "")
	c.Put([]byte{2, 2, 2}, "")

	closest := c.Closest([]byte{2, 3, 3}).Key

	assert.Equal(t, closest, []byte{2, 2, 2})
}

func TestCachePutGet(t *testing.T) {
	locus := []byte{1, 1, 1}
	c := NewCache[string](locus, 3, 0)

	c.Put([]byte{2, 2, 2}, "222")
	c.Put([]byte{3, 3, 3}, "333")
	c.Put([]byte{1, 1, 2}, "112")

	v, _ := c.Get([]byte{2, 2, 2})
	require.Equal(t, "222", v)
	v, _ = c.Get([]byte{3, 3, 3})
	require.Equal(t, "333", v)
	v, _ = c.Get([]byte{1, 1, 2})
	require.Equal(t, "112", v)

	// this should not evict 112
	c.Put([]byte{1, 1, 3}, "113")
	v, _ = c.Get([]byte{1, 1, 3})
	require.Equal(t, "113", v)

	require.Equal(t, 3, c.Count())
}

func TestCacheCloser(t *testing.T) {
	locus := []byte{0, 0, 0, 0}
	c := NewCache[string](locus, 10, 0)

	const N = 10000
	rng := mrand.New(mrand.NewSource(0))
	for i := 0; i < N; i++ {
		buf := [4]byte{}
		rng.Read(buf[:])
		c.Put(buf[:], "")
	}
	c.ForEach(func(e Entry[string]) bool {
		assert.Greater(t, Leading0s(e.Key), 8)
		t.Log(e)
		return true
	})
}

func TestCacheForEachAsc(t *testing.T) {
	locus := []byte{0, 0, 0, 0}
	c := NewCache[string](locus, 100, 0)
	const N = 10000
	rng := mrand.New(mrand.NewSource(0))
	for i := 0; i < N; i++ {
		buf := [4]byte{}
		rng.Read(buf[:])
		c.Put(buf[:], "")
	}

	k := []byte{1, 1, 1, 1}
	var last []byte
	c.ForEachAsc(k, func(e Entry[string]) bool {
		if last != nil {
			require.True(t, DistanceGt(k, e.Key, last), "%v not further than %v", e.Key, last)
		}
		last = e.Key
		return true
	})
}
