package kademlia

import (
	"bytes"
)

type Entry[V any] struct {
	Key   []byte
	Value V
}

type Cache[V any] struct {
	locus        []byte
	minPerBucket int
	count, max   int
	buckets      []map[string]Entry[V]
}

func NewCache[V any](locus []byte, max, minPerBucket int) *Cache[V] {
	if max < 1 {
		panic("max < 1")
	}
	kc := &Cache[V]{
		minPerBucket: minPerBucket,
		max:          max,
		locus:        locus,
	}
	return kc
}

// Get returns the value at key
func (kc *Cache[V]) Get(key []byte) (ret V, exists bool) {
	b := kc.bucket(key)
	if b == nil {
		return ret, false
	}
	e, ok := b[string(key)]
	if !ok {
		return ret, false
	}
	return e.Value, true
}

// Put puts an entry in the cache, replacing the entry at that key.
func (kc *Cache[V]) Put(key []byte, v V) (evicted *Entry[V]) {
	e := Entry[V]{Key: key, Value: v}
	lz := kc.bucketIndex(key)
	// create buckets up to lz
	for len(kc.buckets) <= lz {
		kc.buckets = append(kc.buckets, map[string]Entry[V]{})
	}
	b := kc.buckets[lz]
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

// WouldAdd returns true if the key would add a new entry
func (kc *Cache[V]) WouldAdd(key []byte) bool {
	if kc.Contains(key) {
		return false
	}
	return kc.WouldPut(key)
}

// WouldPut returns true if a call to Put with key would add or overwrite an entry.
func (kc *Cache[V]) WouldPut(key []byte) bool {
	i := kc.bucketIndex(key)
	// if we are below the max or we would create a bucket.
	if kc.count+1 <= kc.max || i >= len(kc.buckets) {
		return true
	}
	// i will be a valid bucket
	i--
	for ; i >= 0; i-- {
		b := kc.buckets[i]
		// if there is something to evict, return true
		if len(b) < kc.minPerBucket {
			return true
		}
	}
	return false
}

// Contains returns true if the key is in the cache
func (kc *Cache[V]) Contains(key []byte) bool {
	_, exists := kc.Get(key)
	return exists
}

// Delete removes the entry at the given key
func (kc *Cache[V]) Delete(key []byte) *Entry[V] {
	b := kc.bucket(key)
	e, exists := b[string(key)]
	if !exists {
		return nil
	}
	delete(b, string(key))
	kc.count--
	return &e
}

func (kc *Cache[V]) ForEach(fn func(e Entry[V]) bool) {
	// reverse iteration so the closest keys are first
	for i := len(kc.buckets) - 1; i >= 0; i-- {
		b := kc.buckets[i]
		for _, e := range b {
			if cont := fn(e); !cont {
				return
			}
		}
	}
}

// Closest returns the Entry in the cache where e.Key is closest to key.
func (kc *Cache[V]) Closest(key []byte) *Entry[V] {
	b := kc.bucket(key)
	var minDist []byte
	var closestEntry *Entry[V]
	dist := make([]byte, len(kc.locus))
	for _, e := range b {
		XORBytes(dist, e.Key, key)
		if minDist == nil || bytes.Compare(dist, minDist) < 0 {
			minDist = append(minDist[:0], dist...)
			closestEntry = &e
		}
	}
	return closestEntry
}

// IsFull returns whether the cache is full
// further calls to Put will attempt an eviction.
func (kc *Cache[V]) IsFull() bool {
	return kc.count >= kc.max
}

// Count returns the number of entries in the cache.
func (kc *Cache[V]) Count() int {
	return kc.count
}

func (kc *Cache[V]) AcceptingPrefixLen() int {
	if kc.count+1 < kc.max {
		return 0
	}
	for i, b := range kc.buckets {
		if len(b) > kc.minPerBucket {
			return i + 1
		}
	}
	return len(kc.buckets)
}

func (kc *Cache[V]) Locus() []byte {
	return kc.locus
}

// ForEachMatching calls fn with every entry where the key matches prefix
// for the leading nbits.  If nbits < len(prefix/8) it panics
func (kc *Cache[V]) ForEachMatching(prefix []byte, nbits int, fn func(Entry[V])) {
	lz := kc.bucketIndex(prefix)
	for i, b := range kc.buckets {
		if lz <= i {
			for _, e := range b {
				if HasPrefix(e.Key, prefix, nbits) {
					fn(e)
				}
			}
		}
	}
}

func (kc *Cache[V]) bucket(key []byte) map[string]Entry[V] {
	i := kc.bucketIndex(key)
	if i < len(kc.buckets) {
		return kc.buckets[i]
	}
	return nil
}

func (kc *Cache[V]) bucketIndex(key []byte) int {
	dist := make([]byte, len(kc.locus))
	XORBytes(dist, kc.locus, key)
	return Leading0s(dist)
}

func (kc *Cache[V]) evict() *Entry[V] {
	n := -1
	for i, b := range kc.buckets {
		if len(b) > kc.minPerBucket && len(b) != 0 {
			n = i
			break
		}
	}
	if n < 0 {
		return nil
	}

	b := kc.buckets[n]
	k := getOne(b)
	ent := b[k]
	delete(b, k)
	kc.count--
	return &ent
}

func getOne[K comparable, V any, M ~map[K]V](m M) K {
	for k := range m {
		return k
	}
	panic("getOne called on empty map")
}
