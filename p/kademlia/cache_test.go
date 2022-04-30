package kademlia

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestClosest(t *testing.T) {
	locus := []byte{1, 1, 1}
	c := NewCache[string](locus, 10, 1)

	c.Put([]byte{3, 3, 3}, "")
	c.Put([]byte{2, 2, 2}, "")

	closest := c.Closest([]byte{2, 3, 3}).Key

	assert.Equal(t, closest, []byte{2, 2, 2})
}
