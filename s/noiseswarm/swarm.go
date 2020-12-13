package noiseswarm

import (
	"context"
	mrand "math/rand"
	"sync"
	"time"

	"github.com/brendoncarroll/go-p2p"
	"github.com/pkg/errors"
)

var _ p2p.SecureSwarm = &Swarm{}

// Overhead is the per message overhead.
// MTU will be smaller than for the underlying swarm's MTU by Overhead
const Overhead = 4 + 16

type Swarm struct {
	swarm      p2p.Swarm
	privateKey p2p.PrivateKey
	localID    p2p.PeerID

	cf context.CancelFunc

	mu             sync.RWMutex
	lowerToSession map[string]*session
}

func New(x p2p.Swarm, privateKey p2p.PrivateKey) *Swarm {
	ctx, cf := context.WithCancel(context.Background())
	s := &Swarm{
		swarm:      x,
		privateKey: privateKey,
		localID:    p2p.NewPeerID(privateKey.Public()),

		cf: cf,

		lowerToSession: make(map[string]*session),
	}
	s.OnTell(nil)
	go s.cleanupLoop(ctx)
	return s
}

func (s *Swarm) Tell(ctx context.Context, addr p2p.Addr, data []byte) error {
	dst := addr.(Addr)
	return s.withDialedSession(ctx, dst, func(sess *session) error {
		return sess.tell(ctx, data)
	})
}

func (s *Swarm) OnTell(fn p2p.TellHandler) {
	if fn == nil {
		fn = p2p.NoOpTellHandler
	}
	s.swarm.OnTell(func(msg *p2p.Message) {
		s.fromBelow(msg, fn)
	})
}

func (s *Swarm) Close() error {
	s.cf()
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
	if exists {
		if err := sess.waitHandshake(ctx); err != nil {
			return nil, p2p.ErrPublicKeyNotFound
		}
		if sess.getRemotePeerID() == target.ID {
			return sess.getRemotePublicKey(), nil
		}
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
	newSession := func() *session {
		return newSession(false, s.privateKey, func(ctx context.Context, data []byte) error {
			return s.swarm.Tell(ctx, msg.Src, data)
		})
	}
	// if we get an error that requires clearing the session, see if feeding the message to a new session works
	for i := 0; i < 2; i++ {
		sess, _ := s.getOrCreateSession(msg.Src, newSession)
		up, err := sess.handle(msg.Payload)
		if err != nil {
			if shouldClearSession(err) {
				s.deleteSession(msg.Src, sess)
				continue
			} else {
				return
			}
		} else {
			if up != nil {
				next(&p2p.Message{
					Src: Addr{
						ID:   sess.getRemotePeerID(),
						Addr: msg.Src,
					},
					Dst: Addr{
						ID:   s.localID,
						Addr: msg.Dst,
					},
					Payload: up,
				})
			}
			return
		}
	}
}

// withDialedSession calls dialSession until it doesn't error, retrying if necessary.
// then it calls fn with the session.  fn will only be called once, although dialSession may be
// called multiple times.
func (s *Swarm) withDialedSession(ctx context.Context, raddr Addr, fn func(s *session) error) error {
	var err error
	for i := 0; i < 10; i++ {
		sess, err := s.dialSession(ctx, raddr.Addr)
		if err == nil {
			actualPeerID := sess.getRemotePeerID()
			if actualPeerID != raddr.ID {
				s.deleteSession(raddr.Addr, sess)
				return errors.Errorf("wrong peer HAVE: %v WANT: %v", actualPeerID, raddr.ID)
			}
			return fn(sess)
		}
		time.Sleep(backoffTime(i, time.Second))
	}
	return err
}

// dialSession get's a session from the cache, or creates a new one.
// if a new session is created dialSession iniates a handshake and waits for it to complete or error.
func (s *Swarm) dialSession(ctx context.Context, lowerRaddr p2p.Addr) (*session, error) {
	sess, created := s.getOrCreateSession(lowerRaddr, func() *session {
		return newSession(true, s.privateKey, func(ctx context.Context, data []byte) error {
			return s.swarm.Tell(ctx, lowerRaddr, data)
		})
	})
	if created {
		if err := sess.startHandshake(ctx); err != nil {
			s.deleteSession(lowerRaddr, sess)
			return nil, err
		}
	}
	if err := sess.waitHandshake(ctx); err != nil {
		return nil, err
	}
	return sess, nil
}

// getOrCreate session returns an existing session or calls newSession to create one.
// if newSession is called it will return the session, and true otherwise false.
func (s *Swarm) getOrCreateSession(lowerRaddr p2p.Addr, newSession func() *session) (sess *session, created bool) {
	now := time.Now()
	s.mu.RLock()
	sess, exists := s.lowerToSession[lowerRaddr.Key()]
	s.mu.RUnlock()
	if exists {
		if !sess.isExpired(now) {
			return sess, false
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	sess, exists = s.lowerToSession[lowerRaddr.Key()]
	if exists {
		if !sess.isExpired(now) {
			return sess, false
		}
	}
	sess = newSession()
	s.lowerToSession[lowerRaddr.Key()] = sess
	return sess, true
}

// delete session deletes the session at lowerRaddr if it exists
// if a different session than x, or no session is found deleteSession is a noop
func (s *Swarm) deleteSession(lowerRaddr p2p.Addr, x *session) {
	s.mu.Lock()
	y := s.lowerToSession[lowerRaddr.Key()]
	if x == y {
		delete(s.lowerToSession, lowerRaddr.Key())
	}
	s.mu.Unlock()
}

func (s *Swarm) cleanupLoop(ctx context.Context) {
	ticker := time.NewTicker(MaxSessionLife)
	defer ticker.Stop()
	for {
		now := time.Now()
		s.mu.Lock()
		for k, sess := range s.lowerToSession {
			if sess.isExpired(now) {
				delete(s.lowerToSession, k)
			}
		}
		s.mu.Unlock()
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

func backoffTime(n int, max time.Duration) time.Duration {
	d := time.Millisecond * time.Duration(1<<n)
	if d > max {
		d = max
	}
	jitter := time.Duration(mrand.Intn(100))
	d = (d * jitter / 100) + d
	return d
}
