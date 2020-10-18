package kademlia

import (
	"bytes"
	"math/bits"
)

type Entry struct {
	Key   []byte
	Value interface{}
}

type Cache struct {
	locus        []byte
	minPerBucket int
	count, max   int
	entries      []map[string]Entry
}

func NewCache(locus []byte, max, minPerBucket int) *Cache {
	if max < 1 {
		panic("max < 1")
	}
	kc := &Cache{
		minPerBucket: minPerBucket,
		max:          max,
		locus:        locus,
	}
	return kc
}

// Lookup returns the value at key
func (kc *Cache) Lookup(key []byte) interface{} {
	dist := make([]byte, len(kc.locus))
	XORBytes(dist, key, kc.locus)
	lz := Leading0s(dist)

	if len(kc.entries) <= lz {
		return nil
	}
	b := kc.entries[lz]
	e, ok := b[string(key)]
	if !ok {
		return nil
	}
	return e.Value
}

// Put puts an entry in the cache, replacing the entry at that key.
func (kc *Cache) Put(key []byte, v interface{}) (evicted *Entry) {
	e := Entry{Key: key, Value: v}
	dist := make([]byte, len(kc.locus))
	XORBytes(dist, kc.locus, e.Key)
	lz := Leading0s(dist)

	for len(kc.entries) <= lz {
		kc.entries = append(kc.entries, map[string]Entry{})
	}
	b := kc.entries[lz]
	if _, exists := b[string(e.Key)]; !exists {
		kc.count++
	}
	b[string(e.Key)] = e

	needToEvict := kc.count > kc.max
	if needToEvict {
		return kc.evict()
	}
	return nil
}

// Delete removes the entry at the given key
func (kc *Cache) Delete(key []byte) *Entry {
	dist := make([]byte, len(kc.locus))
	XORBytes(dist, kc.locus, key)
	lz := Leading0s(dist)

	if len(kc.entries) < lz {
		return nil
	}
	b := kc.entries[lz]
	e, exists := b[string(key)]
	if !exists {
		return nil
	}
	delete(b, string(key))
	kc.count--
	return &e
}

func (kc *Cache) ForEach(fn func(e Entry) bool) {
	for i := len(kc.entries) - 1; i >= 0; i-- {
		b := kc.entries[i]
		for _, e := range b {
			cont := fn(e)
			if !cont {
				return
			}
		}
	}
}

// Closest returns the Entry in the cache where e.Key is closest to key.
func (kc *Cache) Closest(key []byte) *Entry {
	dist := make([]byte, len(kc.locus))
	XORBytes(dist, kc.locus, key)
	lz := Leading0s(dist)

	if len(kc.entries) < lz {
		return nil
	}
	b := kc.entries[lz]

	var minDist []byte
	var closestEntry *Entry
	for _, e := range b {
		XORBytes(dist, e.Key, key)
		if minDist == nil || bytes.Compare(dist, minDist) < 0 {
			minDist = append([]byte{}, dist...)
			closestEntry = &e
		}
	}

	return closestEntry
}

// IsFull returns whether the cache is full
// further calls to Put will attempt an eviction.
func (kc *Cache) IsFull() bool {
	return kc.count >= kc.max
}

// WouldAccept returns the number of matching bits that would cause an
// entry to make it into the cache.
func (kc *Cache) WouldAccept() int {
	for i, b := range kc.entries {
		if len(b) < kc.minPerBucket {
			return i
		}
	}
	return len(kc.entries)
}

// Count returns the number of entries in the cache.
func (kc *Cache) Count() int {
	return kc.count
}

func (kc *Cache) evict() *Entry {
	n := -1
	for i, b := range kc.entries {
		if len(b) > kc.minPerBucket {
			n = i
			break
		}
	}
	if n < 0 {
		return nil
	}

	b := kc.entries[n]
	k := getOne(b)
	ent := b[k]
	delete(b, k)
	kc.count--
	return &ent
}

func Leading0s(x []byte) int {
	total := 0
	for i := range x {
		lz := bits.LeadingZeros8(x[i])
		total += lz
		if lz < 8 {
			break
		}
	}
	return total
}

func XORBytes(dst, a, b []byte) {
	l := len(a)
	if len(b) < len(a) {
		l = len(b)
	}
	for i := 0; i < l; i++ {
		dst[i] = a[i] ^ b[i]
	}
}

func getOne(m map[string]Entry) string {
	for k := range m {
		return k
	}
	panic("getOne called on empty map")
}
