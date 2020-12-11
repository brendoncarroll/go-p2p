package noiseswarm

import (
	"context"
	"log"
	"sync"

	"github.com/brendoncarroll/go-p2p"
	"github.com/sirupsen/logrus"
)

var _ p2p.SecureSwarm = &Swarm{}

const Overhead = 4 + 16

type Swarm struct {
	swarm      p2p.Swarm
	privateKey p2p.PrivateKey
	localID    p2p.PeerID

	mu             sync.RWMutex
	lowerToSession map[string]*session
}

func New(x p2p.Swarm, privateKey p2p.PrivateKey) *Swarm {
	s := &Swarm{
		swarm:      x,
		privateKey: privateKey,
		localID:    p2p.NewPeerID(privateKey.Public()),

		lowerToSession: make(map[string]*session),
	}

	return s
}

func (s *Swarm) Tell(ctx context.Context, addr p2p.Addr, data []byte) error {
	dst := addr.(Addr)
	return s.withSession(ctx, dst, func(sess *session) error {
		return sess.tell(ctx, data)
	})
}

func (s *Swarm) OnTell(fn p2p.TellHandler) {
	s.swarm.OnTell(func(msg *p2p.Message) {
		s.fromBelow(msg, fn)
	})
}

func (s *Swarm) Close() error {
	return s.swarm.Close()
}

func (s *Swarm) LocalAddrs() (addrs []p2p.Addr) {
	for _, addr := range s.swarm.LocalAddrs() {
		addrs = append(addrs, Addr{
			ID:   p2p.NewPeerID(s.privateKey.Public()),
			Addr: addr,
		})
	}
	return addrs
}

func (s *Swarm) LookupPublicKey(ctx context.Context, addr p2p.Addr) (p2p.PublicKey, error) {
	target := addr.(Addr)

	s.mu.RLock()
	sess, exists := s.lowerToSession[target.Addr.Key()]
	s.mu.RUnlock()
	if exists && sess.remotePeerID() == target.ID {
		return sess.remotePublicKey(), nil
	}
	return nil, p2p.ErrPublicKeyNotFound
}

func (s *Swarm) PublicKey() p2p.PublicKey {
	return s.privateKey.Public()
}

func (s *Swarm) MTU(ctx context.Context, addr p2p.Addr) int {
	target := addr.(Addr)
	return s.swarm.MTU(ctx, target.Addr) - Overhead
}

func (s *Swarm) fromBelow(msg *p2p.Message, next p2p.TellHandler) {
	src := msg.Src
	log.Println("recv", src)
	s.mu.Lock()
	sess, exists := s.lowerToSession[src.Key()]
	if !exists {
		sess = newSession(false, s.privateKey, func(ctx context.Context, data []byte) error {
			return s.swarm.Tell(ctx, src, data)
		})
		s.lowerToSession[src.Key()] = sess
	}
	s.mu.Unlock()
	up, err := sess.handle(msg.Payload)
	if err != nil {
		logrus.Error(err)
		return
	}
	if up != nil {
		next(&p2p.Message{
			Src: Addr{
				ID:   sess.remotePeerID(),
				Addr: msg.Src,
			},
			Dst: Addr{
				ID:   s.localID,
				Addr: msg.Dst,
			},
			Payload: up,
		})
	}
}

func (s *Swarm) withSession(ctx context.Context, raddr Addr, fn func(s *session) error) error {
	s.mu.RLock()
	sess, exists := s.lowerToSession[raddr.Addr.Key()]
	s.mu.RUnlock()
	if exists {
		return fn(sess)
	}
	s.mu.Lock()
	sess, exists = s.lowerToSession[raddr.Addr.Key()]
	if exists {
		return fn(sess)
	}
	sess = newSession(true, s.privateKey, func(ctx context.Context, data []byte) error {
		return s.swarm.Tell(ctx, raddr.Addr, data)
	})
	s.lowerToSession[raddr.Addr.Key()] = sess
	s.mu.Unlock()
	if err := sess.startHandshake(ctx); err != nil {
		return err
	}
	if err := sess.waitHandshake(ctx); err != nil {
		return err
	}
	return fn(sess)
}
