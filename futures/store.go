package futures

import (
	"sync"

	"golang.org/x/exp/maps"
)

type Store[K comparable, V any] struct {
	mu sync.RWMutex
	m  map[K]*Promise[V]
}

func NewStore[K comparable, V any]() *Store[K, V] {
	return &Store[K, V]{
		m: make(map[K]*Promise[V]),
	}
}

func (s *Store[K, V]) Get(k K) *Promise[V] {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.m[k]
}

func (s *Store[K, V]) GetOrCreate(k K) (*Promise[V], bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	p, exists := s.m[k]
	if !exists {
		p = NewPromise[V]()
		s.m[k] = p
	}
	return p, !exists
}

func (s *Store[K, V]) Succeed(k K, x V) {
	s.mu.Lock()
	defer s.mu.Unlock()
	fut, exists := s.m[k]
	if exists {
		delete(s.m, k)
		fut.Succeed(x)
	}
}

func (s *Store[K, V]) Fail(k K, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	fut, exists := s.m[k]
	if exists {
		delete(s.m, k)
		fut.Fail(err)
	}
}

func (s *Store[K, V]) Delete(k K, p *Promise[V]) {
	s.mu.Lock()
	defer s.mu.Unlock()
	p2 := s.m[k]
	if p == nil || p == p2 {
		delete(s.m, k)
	}
}

func (s *Store[K, V]) ForEach(fn func(k K, v *Promise[V]) bool) bool {
	s.mu.RLock()
	keys := maps.Keys(s.m)
	s.mu.RUnlock()
	for _, k := range keys {
		v, exists := s.m[k]
		if exists {
			if !fn(k, v) {
				return false
			}
		}
	}
	return true
}
