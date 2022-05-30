package kademlia

import (
	"bytes"
	"fmt"
	"time"

	"golang.org/x/exp/maps"
	"golang.org/x/exp/slices"
)

// Entry is an entry in the cache.
type Entry[V any] struct {
	Key       []byte
	Value     V
	ExpiresAt time.Time
}

func (e Entry[V]) String() string {
	return fmt.Sprintf("(%q -> %v, %v)", e.Key, e.Value, e.ExpiresAt)
}

type Cache[V any] struct {
	locus        []byte
	minPerBucket int
	count, max   int
	buckets      []*bucket[V]
}

// NewCache returns a Cache with the provided parameters
// NewCache will panic if max is < minPerBucket * 8 * len(locus)
// i.e. If the locus is 256 bits long, then you can have anywhere
// from 0 to 256 buckets, and max must be sufficiently large to respect
// each of those 256 buckets having a minimum number of keys.
func NewCache[V any](locus []byte, max, minPerBucket int) *Cache[V] {
	if max < 0 {
		panic("max < 0")
	}
	if minPerBucket*8*len(locus) > max {
		panic(fmt.Sprintf("max must be >= 8 * len(locus) * minPerBucket, max=%d minPerBucket=%d", max, minPerBucket))
	}
	kc := &Cache[V]{
		minPerBucket: minPerBucket,
		max:          max,
		locus:        append([]byte{}, locus...),
	}
	return kc
}

// Get returns the value at key
func (kc *Cache[V]) Get(key []byte) (ret V, exists bool) {
	b := kc.getBucket(key)
	if b == nil {
		return ret, false
	}
	return b.get(key)
}

// Put puts an entry in the cache, replacing the entry at that key.
// Put returns the evicted entry if there was one, and whether or not the Put
// had an effect.
func (kc *Cache[V]) Put(key []byte, v V) (evicted *Entry[V], added bool) {
	if kc.max == 0 {
		return nil, false
	}
	e := Entry[V]{
		Key:   slices.Clone(key),
		Value: v,
	}
	lz := kc.bucketIndex(key)
	// create buckets up to lz
	for len(kc.buckets) <= lz {
		kc.buckets = append(kc.buckets, newBucket[V]())
	}
	b := kc.buckets[lz]
	added = b.put(e)
	if added {
		kc.count++
	}
	needToEvict := kc.count > kc.max
	if needToEvict {
		evicted = kc.evict()
		added = !bytes.Equal(e.Key, evicted.Key)
	}
	return evicted, added
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
		if b.len() < kc.minPerBucket {
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
	b := kc.getBucket(key)
	if b == nil {
		return nil
	}
	e, deleted := b.delete(key)
	if deleted {
		kc.count--
	}
	return &e
}

func (kc *Cache[V]) ForEach(fn func(e Entry[V]) bool) {
	kc.ForEachAsc(kc.locus, fn)
}

// ForEachAsc calls fn with entries in ascending distance from k
func (kc *Cache[V]) ForEachAsc(k []byte, fn func(e Entry[V]) bool) {
	d := Distance(kc.locus, k)
	lz := Leading0s(d)
	// everything in these buckets will have lz bits matching k.
	for i := lz; i < len(kc.buckets); i++ {
		if !kc.buckets[i].forEachAsc(k, fn) {
			return
		}
	}
	// each bucket will have < lz bits matching k.
	for i := min(lz-1, len(kc.buckets)-1); i >= 0; i-- {
		if !kc.buckets[i].forEachAsc(k, fn) {
			return
		}
	}
}

// Closest returns the Entry in the cache where e.Key is closest to key.
func (kc *Cache[V]) Closest(key []byte) (ret *Entry[V]) {
	kc.ForEachAsc(key, func(e Entry[V]) bool {
		ret = &e
		return false
	})
	return ret
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
		if b.len() > kc.minPerBucket {
			return i + 1
		}
	}
	return len(kc.buckets)
}

func (kc *Cache[V]) Locus() []byte {
	return kc.locus
}

// ForEachMatching calls fn with every entry where the key matches prefix
// for the leading nbits.  If nbits < len(prefix/8) it panics.
func (kc *Cache[V]) ForEachMatching(prefix []byte, nbits int, fn func(Entry[V]) bool) {
	l := nbits / 8
	if l%8 > 0 {
		l++
	}
	kc.ForEachAsc(prefix[:l], func(e Entry[V]) bool {
		if HasPrefix(e.Key, prefix, nbits) {
			return fn(e)
		}
		return true
	})
}

// ForEachCloser calls fn with all the entries in the Cache which are closer to x
// than they are to the locus.
func (kc *Cache[V]) ForEachCloser(x []byte, fn func(Entry[V]) bool) {
	kc.ForEachAsc(x, func(e Entry[V]) bool {
		if !DistanceLt(x, e.Key, kc.locus) {
			return false
		}
		return fn(e)
	})
}

func (kc *Cache[V]) getBucket(key []byte) *bucket[V] {
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
		if b.len() > kc.minPerBucket {
			n = i
			break
		}
	}
	if n < 0 {
		return nil
	}
	b := kc.buckets[n]
	ent := b.evict(kc.locus)
	kc.count--
	return &ent
}

type bucket[V any] struct {
	entries      map[string]Entry[V]
	minExpiresAt time.Time
}

func newBucket[V any]() *bucket[V] {
	return &bucket[V]{
		entries: make(map[string]Entry[V]),
	}
}

func (b *bucket[V]) put(e Entry[V]) (added bool) {
	if _, exists := b.entries[string(e.Key)]; !exists {
		b.entries[string(e.Key)] = e
		b.updateMinExpires(e.ExpiresAt)
		return true
	}
	return false
}

func (b *bucket[V]) get(key []byte) (V, bool) {
	e, exists := b.entries[string(key)]
	return e.Value, exists
}

func (b *bucket[V]) delete(key []byte) (Entry[V], bool) {
	e, exists := b.entries[string(key)]
	delete(b.entries, string(key))
	if e.ExpiresAt == b.minExpiresAt {
		for _, e := range b.entries {
			b.updateMinExpires(e.ExpiresAt)
		}
	}
	return e, exists
}

func (b *bucket[V]) evict(locus []byte) Entry[V] {
	if len(b.entries) < 1 {
		panic("evict from bucket with len=0")
	}
	k := b.pickFurthest(locus)
	e := b.entries[k]
	delete(b.entries, k)
	return e
}

func (b *bucket[V]) pickFurthest(locus []byte) string {
	var furthest string
	for k := range b.entries {
		if furthest == "" || DistanceLt(locus, []byte(k), []byte(furthest)) {
			furthest = k
		}
	}
	return furthest
}

func (b *bucket[V]) len() int {
	return len(b.entries)
}

func (b *bucket[V]) forEachAsc(locus []byte, fn func(e Entry[V]) bool) bool {
	keys := maps.Keys(b.entries)
	slices.SortFunc(keys, func(a, b string) bool {
		return DistanceLt(locus, []byte(a), []byte(b))
	})
	for _, k := range keys {
		if !fn(b.entries[k]) {
			return false
		}
	}
	return true
}

func (b *bucket[V]) updateMinExpires(x time.Time) {
	if x.IsZero() {
		return
	}
	if b.minExpiresAt.IsZero() || x.Before(b.minExpiresAt) {
		b.minExpiresAt = x
	}
}
