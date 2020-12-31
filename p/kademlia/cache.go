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

// Get returns the value at key
func (kc *Cache) Get(key []byte) interface{} {
	b := kc.bucket(key)
	if b == nil {
		return nil
	}
	e, ok := b[string(key)]
	if !ok {
		return nil
	}
	return e.Value
}

// Put puts an entry in the cache, replacing the entry at that key.
func (kc *Cache) Put(key []byte, v interface{}) (evicted *Entry) {
	e := Entry{Key: key, Value: v}
	lz := kc.bucketIndex(key)
	// create buckets up to lz
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

// WouldAdd returns true if the key would add a new entry
func (kc *Cache) WouldAdd(key []byte) bool {
	if kc.Contains(key) {
		return false
	}
	return kc.WouldPut(key)
}

// WouldPut returns true if a call to Put with key would add or overwrite an entry.
func (kc *Cache) WouldPut(key []byte) bool {
	i := kc.bucketIndex(key)
	// if we are below the max or we would create a bucket.
	if kc.count+1 <= kc.max || i >= len(kc.entries) {
		return true
	}
	// i will be a valid bucket
	i--
	for ; i >= 0; i-- {
		b := kc.entries[i]
		// if there is something to evict, return true
		if len(b) < kc.minPerBucket {
			return true
		}
	}
	return false
}

// Contains returns true if the key is in the cache
func (kc *Cache) Contains(key []byte) bool {
	return kc.Get(key) != nil
}

// Delete removes the entry at the given key
func (kc *Cache) Delete(key []byte) *Entry {
	b := kc.bucket(key)
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
			if cont := fn(e); !cont {
				return
			}
		}
	}
}

// Closest returns the Entry in the cache where e.Key is closest to key.
func (kc *Cache) Closest(key []byte) *Entry {
	b := kc.bucket(key)
	var minDist []byte
	var closestEntry *Entry
	dist := make([]byte, len(kc.locus))
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

// Count returns the number of entries in the cache.
func (kc *Cache) Count() int {
	return kc.count
}

func (kc *Cache) AcceptingPrefixLen() int {
	if kc.count+1 < kc.max {
		return 0
	}
	for i, b := range kc.entries {
		if len(b) > kc.minPerBucket {
			return i + 1
		}
	}
	return len(kc.entries)
}

func (kc *Cache) Locus() []byte {
	return kc.locus
}

// ForEachMatching calls fn with every entry where the key matches prefix
// for the leading nbits.  If nbits < len(prefix/8) it panics
func (kc *Cache) ForEachMatching(prefix []byte, nbits int, fn func(Entry)) {
	dist := make([]byte, len(kc.locus))
	XORBytes(dist, kc.locus, prefix)
	lz := Leading0s(dist)
	for i, b := range kc.entries {
		if lz <= i {
			for _, e := range b {
				if HasPrefix(e.Key, prefix, nbits) {
					fn(e)
				}
			}
		}
	}
}

func (kc *Cache) bucket(key []byte) map[string]Entry {
	i := kc.bucketIndex(key)
	if i < len(kc.entries) {
		return kc.entries[i]
	}
	return nil
}

func (kc *Cache) bucketIndex(key []byte) int {
	dist := make([]byte, len(kc.locus))
	XORBytes(dist, kc.locus, key)
	return Leading0s(dist)
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

func HasPrefix(x []byte, prefix []byte, nbits int) bool {
	if nbits > len(prefix)*8 {
		panic("nbits longer than prefix")
	}
	if len(x) < len(prefix) {
		return false
	}
	xor := make([]byte, len(x))
	for i := range prefix {
		xor[i] = x[i] ^ prefix[i]
	}
	lz := 0
	for i := range xor {
		lzi := bits.LeadingZeros8(xor[i])
		lz += lzi
		if lzi < 8 {
			break
		}
	}
	return lz == nbits
}
