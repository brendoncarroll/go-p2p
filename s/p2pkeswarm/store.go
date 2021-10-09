package p2pkeswarm

import (
	"sync"

	"github.com/brendoncarroll/go-p2p"
	"github.com/brendoncarroll/go-p2p/p/p2pke"
)

type store struct {
	privateKey p2p.PrivateKey
	mu         sync.RWMutex
	addrs      map[string]*p2pke.Conn
}

func newStore(privateKey p2p.PrivateKey) *store {
	return &store{
		privateKey: privateKey,
		addrs:      make(map[string]*p2pke.Conn),
	}
}

// withCell calls fn with sc.
// while fn executes, all traffic is gaurenteed to reach the conn passed to fn, there will not be another cell with the same id.
func (s *store) withConn(sid string, fn func(c *p2pke.Conn) error) error {
	conn := s.getOrCreateConn(sid)
	if err := fn(conn); err != nil {
		return err
	}
	return nil
}

func (s *store) getOrCreateConn(sid string) *p2pke.Conn {
	s.mu.RLock()
	conn, exists := s.addrs[sid]
	s.mu.RUnlock()
	if !exists {
		s.mu.Lock()
		conn, exists = s.addrs[sid]
		if !exists {
			conn = p2pke.NewConn(s.privateKey)
			s.addrs[sid] = conn
		}
		s.mu.Unlock()
	}
	return conn
}
