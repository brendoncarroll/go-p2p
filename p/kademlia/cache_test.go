package kademlia

import (
	mrand "math/rand"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCacheClosest(t *testing.T) {
	locus := []byte{1, 1, 1}
	c := NewCache[string](locus, 10, 0)
	now := time.Now()
	expiresAt := now.Add(time.Hour)

	c.Put([]byte{3, 3, 3}, "", now, expiresAt)
	c.Put([]byte{2, 2, 2}, "", now, expiresAt)

	closest := c.Closest([]byte{2, 3, 3}).Key

	assert.Equal(t, closest, []byte{2, 2, 2})
}

func TestCachePutGet(t *testing.T) {
	locus := []byte{1, 1, 1}
	c := NewCache[string](locus, 3, 0)
	now := time.Now()
	expiresAt := now.Add(time.Hour)

	c.Put([]byte{2, 2, 2}, "222", now, expiresAt)
	c.Put([]byte{3, 3, 3}, "333", now, expiresAt)
	c.Put([]byte{1, 1, 2}, "112", now, expiresAt)

	v, _ := c.Get([]byte{2, 2, 2}, now)
	require.Equal(t, "222", v)
	v, _ = c.Get([]byte{3, 3, 3}, now)
	require.Equal(t, "333", v)
	v, _ = c.Get([]byte{1, 1, 2}, now)
	require.Equal(t, "112", v)

	// this should not evict 112
	c.Put([]byte{1, 1, 3}, "113", now, expiresAt)
	v, _ = c.Get([]byte{1, 1, 3}, now)
	require.Equal(t, "113", v)

	require.Equal(t, 3, c.Count())
}

func TestCacheCloser(t *testing.T) {
	locus := []byte{0, 0, 0, 0}
	c := NewCache[string](locus, 10, 0)
	now := time.Now()
	expiresAt := now.Add(time.Hour)

	const N = 10000
	rng := mrand.New(mrand.NewSource(0))
	for i := 0; i < N; i++ {
		buf := [4]byte{}
		rng.Read(buf[:])
		c.Put(buf[:], "", now, expiresAt)
	}
	c.ForEach(nil, func(e Entry[string]) bool {
		assert.Greater(t, LeadingZeros(e.Key), 8)
		t.Log(e)
		return true
	})
}
