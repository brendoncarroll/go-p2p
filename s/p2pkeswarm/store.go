package p2pkeswarm

import (
	"sync"
	"time"

	"github.com/brendoncarroll/go-p2p"
	"github.com/brendoncarroll/go-p2p/p/p2pke"
)

type store struct {
	newChan func(Addr) *p2pke.Channel
	mu      sync.RWMutex
	addrs   map[string]*p2pke.Channel
}

func newStore(newChan func(Addr) *p2pke.Channel) *store {
	return &store{
		newChan: newChan,
		addrs:   make(map[string]*p2pke.Channel),
	}
}

// withLower calls fn with sc.
// while fn executes, all traffic is gaurenteed to reach the conn passed to fn, there will not be another conn with the same id.
func (s *store) withConn(x Addr, fn func(c *p2pke.Channel) error) error {
	conn := s.getOrCreateConn(x.ID, x.Addr)
	if err := fn(conn); err != nil {
		return err
	}
	return nil
}

func (s *store) delete(addr Addr) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.addrs, addrKey(addr.Addr))
}

func (s *store) getOrCreateConn(id p2p.PeerID, addr p2p.Addr) *p2pke.Channel {
	sid := addrKey(addr)
	s.mu.RLock()
	conn, exists := s.addrs[sid]
	s.mu.RUnlock()
	if !exists {
		s.mu.Lock()
		conn, exists = s.addrs[sid]
		if !exists {
			conn = s.newChan(Addr{ID: id, Addr: addr})
			s.addrs[sid] = conn
		}
		s.mu.Unlock()
	}
	return conn
}

func (s *store) cleanup(expireBefore time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for k, c := range s.addrs {
		if c.LastReceived().Before(expireBefore) && c.LastSent().Before(expireBefore) {
			delete(s.addrs, k)
		}
	}
}

func addrKey(x p2p.Addr) string {
	data, err := x.MarshalText()
	if err != nil {
		panic(err)
	}
	return string(data)
}
