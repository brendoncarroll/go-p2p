package kademlia

import (
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

func (kc *Cache) Lookup(key []byte) interface{} {
	dist := XORBytes(key, kc.locus)
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

func (kc *Cache) Add(key []byte, v interface{}) (evicted *Entry) {
	e := Entry{Key: key, Value: v}
	dist := XORBytes(kc.locus, e.Key)
	lz := Leading0s(dist)

	for len(kc.entries) < lz {
		kc.entries = append(kc.entries, map[string]Entry{})
	}
	b := kc.entries[lz]
	b[string(e.Key)] = e
	kc.entries[lz] = b
	kc.count++

	needToEvict := kc.count > kc.max
	if needToEvict {
		return kc.evict()
	}
	return nil
}

func (kc *Cache) Delete(key []byte) *Entry {
	dist := XORBytes(kc.locus, key)
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

func (kc *Cache) evict() *Entry {
	n := 0
	for i := 0; len(kc.entries[i]) <= kc.minPerBucket; i++ {
		n = i
	}
	if n >= len(kc.entries) {
		return nil
	}
	b := kc.entries[n]
	k := getOne(b)
	ent := b[k]
	delete(b, k)
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

func XORBytes(a, b []byte) []byte {
	var y []byte
	if len(a) > len(b) {
		y = make([]byte, len(a))
		for i := range b {
			y[i] = a[i] ^ b[i]
		}
	} else {
		y = make([]byte, len(b))
		for i := range a {
			y[i] = a[i] ^ b[i]
		}
	}

	return y
}

func getOne(m map[string]Entry) string {
	for k := range m {
		return k
	}
	panic("getOne called on empty map")
}
