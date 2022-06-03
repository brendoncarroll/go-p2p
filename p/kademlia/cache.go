package kademlia

import (
	"bytes"
	"fmt"
	"sync"
	"time"

	"golang.org/x/exp/slices"
)

// Entry is an entry in the cache.
type Entry[V any] struct {
	Key       []byte
	Value     V
	CreatedAt time.Time
	ExpiresAt time.Time
}

func (e Entry[V]) String() string {
	return fmt.Sprintf("(%q -> %v, %v %v)", e.Key, e.Value, e.CreatedAt, e.ExpiresAt)
}

func (e Entry[V]) IsExpired(now time.Time) bool {
	if e.ExpiresAt.IsZero() {
		return false
	}
	return e.ExpiresAt.Before(now)
}

// Cache stores data and evicts based on the Kademlia distance metric, and the CreatedAt time.
// Entries closer to the locus, that have existed for longer are more likely to remain in the cache.
type Cache[V any] struct {
	locus        []byte
	minPerBucket int
	max          int

	mu      sync.RWMutex
	count   int
	buckets []*bucket[V]
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
func (kc *Cache[V]) Get(key []byte, now time.Time) (ret V, exists bool) {
	kc.mu.Lock()
	defer kc.mu.Unlock()
	b := kc.getBucket(key)
	if b == nil {
		return ret, false
	}
	e, exists := b.get(key)
	if !exists {
		return ret, false
	}
	return e.Value, true
}

// Put puts an entry in the cache, replacing the entry at that key.
// Put returns the evicted entry if there was one, and whether or not the Put
// had an effect.
func (kc *Cache[V]) Put(key []byte, v V, now, expiresAt time.Time) (evicted *Entry[V], affected bool) {
	return kc.Update(key, func(e Entry[V], exists bool) Entry[V] {
		return Entry[V]{
			CreatedAt: now,
			ExpiresAt: expiresAt,
			Key:       key,
			Value:     v,
		}
	})
}

// Update calls fn with the entry in the cache at key if it exists.
func (kc *Cache[V]) Update(key []byte, fn func(v Entry[V], exists bool) Entry[V]) (evicted *Entry[V], added bool) {
	kc.mu.Lock()
	defer kc.mu.Unlock()
	if kc.max == 0 {
		return nil, false
	}
	lz := kc.bucketIndex(key)
	// create buckets up to lz
	for len(kc.buckets) <= lz {
		kc.buckets = append(kc.buckets, newBucket[V](kc.locus))
	}
	b := kc.buckets[lz]
	added = b.update(key, fn)
	if added {
		kc.count++
	}
	needToEvict := kc.count > kc.max
	if needToEvict {
		evicted = kc.evict()
		added = !bytes.Equal(key, evicted.Key)
	}
	return evicted, added
}

// WouldAdd returns true if the key would add a new entry
func (kc *Cache[V]) WouldAdd(key []byte, now time.Time) bool {
	if kc.Contains(key, now) {
		return false
	}
	return kc.WouldPut(key)
}

// WouldPut returns true if a call to Put with key would add or overwrite an entry.
func (kc *Cache[V]) WouldPut(key []byte) bool {
	kc.mu.RLock()
	defer kc.mu.RUnlock()
	i := kc.bucketIndex(key)
	// if we are below the max or we would create a bucket.
	if kc.count+1 <= kc.max || i >= len(kc.buckets) {
		return true
	}
	if _, exists := kc.buckets[i].get(key); exists {
		return true
	}
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
func (kc *Cache[V]) Contains(key []byte, now time.Time) bool {
	_, exists := kc.Get(key, now)
	return exists
}

// Delete removes the entry at the given key
func (kc *Cache[V]) Delete(key []byte) *Entry[V] {
	kc.mu.Lock()
	defer kc.mu.Unlock()
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

// ForEach calls fn with entries.
// All of the entries with n bits in common with k will be emitted
// before any of the entries with n-1 bits in common with k.
func (kc *Cache[V]) ForEach(k []byte, fn func(e Entry[V]) bool) {
	kc.mu.RLock()
	defer kc.mu.RUnlock()
	d := Distance(kc.locus, k)
	lz := LeadingZeros(d)
	// everything in these buckets will have lz bits matching k.
	for i := lz; i < len(kc.buckets); i++ {
		if !kc.buckets[i].forEach(k, fn) {
			return
		}
	}
	// each bucket will have < lz bits matching k.
	for i := min(lz-1, len(kc.buckets)-1); i >= 0; i-- {
		if !kc.buckets[i].forEach(k, fn) {
			return
		}
	}
}

// Closest returns the Entry in the cache where e.Key is closest to key.
func (kc *Cache[V]) Closest(key []byte) (ret *Entry[V]) {
	kc.ForEach(key, func(e Entry[V]) bool {
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
	kc.ForEach(prefix[:l], func(e Entry[V]) bool {
		if HasPrefix(e.Key, prefix, nbits) {
			return fn(e)
		}
		return true
	})
}

// ForEachCloser calls fn with all the entries in the Cache which are closer to x
// than they are to the locus.
func (kc *Cache[V]) ForEachCloser(x []byte, fn func(Entry[V]) bool) {
	kc.ForEach(x, func(e Entry[V]) bool {
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
	return LeadingZeros(dist)
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

// Expire expires items from the cache and appends them to out
func (kc *Cache[V]) Expire(out []Entry[V], now time.Time) []Entry[V] {
	kc.mu.Lock()
	defer kc.mu.Unlock()
	for _, b := range kc.buckets {
		if b.minExpiresAt.Before(now) {
			out = b.expire(out, now)
		}
	}
	return out
}

type bucket[V any] struct {
	locus        []byte
	entries      map[string]Entry[V]
	minExpiresAt time.Time
}

func newBucket[V any](locus []byte) *bucket[V] {
	return &bucket[V]{
		locus:   locus,
		entries: make(map[string]Entry[V]),
	}
}

// get retrieves the entry at the key.
func (b *bucket[V]) get(key []byte) (ret Entry[V], exists bool) {
	e, exists := b.entries[string(key)]
	return e, exists
}

func (b *bucket[V]) update(key []byte, fn func(e Entry[V], exists bool) Entry[V]) (added bool) {
	prev, exists := b.get(key)
	next := fn(prev, exists)
	next.Key = append([]byte{}, next.Key...)
	if !bytes.Equal(key, next.Key) {
		panic(next.Key)
	}
	b.put(next)
	return !exists
}

// put replaces an entry with the same key in the bucket.
func (bu *bucket[V]) put(e Entry[V]) {
	bu.entries[string(e.Key)] = e
	bu.updateMinExpires(e.ExpiresAt)
}

func (b *bucket[V]) delete(key []byte) (ret Entry[V], exists bool) {
	ret, exists = b.entries[string(key)]
	if exists {
		delete(b.entries, string(key))
		b.minExpiresAt = time.Time{}
		for _, e := range b.entries {
			b.updateMinExpires(e.ExpiresAt)
		}
	}
	return ret, exists
}

func (b *bucket[V]) evict(locus []byte) Entry[V] {
	if len(b.entries) < 1 {
		panic("evict from bucket with len=0")
	}
	var maxIndex string
	for i := range b.entries {
		if b.entries[i].CreatedAt.After(b.entries[maxIndex].CreatedAt) {
			maxIndex = i
		}
	}
	e := b.entries[maxIndex]
	delete(b.entries, maxIndex)
	return e
}

func (b *bucket[V]) expire(ret []Entry[V], now time.Time) []Entry[V] {
	for k, e := range b.entries {
		if e.IsExpired(now) {
			ret = append(ret, e)
			delete(b.entries, k)
		}
	}
	return ret
}

func (b *bucket[V]) len() int {
	return len(b.entries)
}

func (b *bucket[V]) forEach(locus []byte, fn func(e Entry[V]) bool) bool {
	var ents []Entry[V]
	for _, e := range b.entries {
		ents = append(ents, e)
	}
	slices.SortFunc(ents, func(a, b Entry[V]) bool {
		return DistanceLt(locus, a.Key, b.Key)
	})
	for _, e := range ents {
		if !fn(e) {
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
