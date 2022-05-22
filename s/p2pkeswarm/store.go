package p2pkeswarm

import (
	"sync"
)

type store[K comparable, V any] struct {
	mu sync.RWMutex
	m  map[K]V
}

func newStore[K comparable, V any]() *store[K, V] {
	return &store[K, V]{
		m: make(map[K]V),
	}
}

func (s *store[K, V]) get(k K) (V, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	v, exists := s.m[k]
	return v, exists
}

func (s *store[K, V]) getOrCreate(k K, fn func() V) V {
	s.mu.Lock()
	defer s.mu.Unlock()
	v, exists := s.m[k]
	if !exists {
		v = fn()
		s.m[k] = v
	}
	return v
}

// purge applies the predicate fn to all items in the store.
// If fn returns false, the item is deleted.
func (s *store[K, V]) purge(fn func(k K, v V) bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for k, v := range s.m {
		if !fn(k, v) {
			delete(s.m, k)
		}
	}
}

func (s *store[K, V]) deleteMatching(k K, fn func(v V) bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	v, exists := s.m[k]
	if exists && fn(v) {
		delete(s.m, k)
	}
}
