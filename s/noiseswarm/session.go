package noiseswarm

import (
	"context"
	"sync"
	"time"

	"github.com/brendoncarroll/go-p2p"
)

const (
	MaxSessionLife     = time.Minute
	MaxSessionMessages = (1 << 31) - 1
	SessionIdleTimeout = 60 * time.Second

	HandshakeTimeout = 3 * time.Second

	// SigPurpose is the purpose passed to p2p.Sign when signing
	// channel bindings.
	// Your application should not reuse this purpose with the privateKey used for the swarm.
	SigPurpose = "p2p/noiseswarm/channel"
)

type session struct {
	createdAt  time.Time
	initiator  bool
	privateKey p2p.PrivateKey
	send       func(context.Context, []byte) error

	mu       sync.Mutex
	lastRecv time.Time
	state    state
	// handshake
	remotePublicKey p2p.PublicKey
	handshakeDone   chan struct{}
}

func newSession(initiator bool, privateKey p2p.PrivateKey, send func(context.Context, []byte) error) *session {
	var initialState state
	if initiator {
		initialState = newAwaitRespState(privateKey)
	} else {
		initialState = newAwaitInitState(privateKey)
	}
	now := time.Now()
	return &session{
		createdAt:  now,
		lastRecv:   now,
		privateKey: privateKey,
		initiator:  initiator,
		send:       send,

		state:         initialState,
		handshakeDone: make(chan struct{}),
	}
}

func (s *session) startHandshake(ctx context.Context) error {
	s.mu.Lock()
	st, ok := s.state.(*awaitRespState)
	if !ok {
		s.mu.Unlock()
		return nil
	}
	msg := newMessage(s.outDirection(), countInit)
	out, _, _, err := st.hsstate.WriteMessage(msg, nil)
	if err != nil {
		panic(err)
	}
	s.mu.Unlock()
	return s.send(ctx, out)
}

func (s *session) upward(ctx context.Context, in []byte) (up []byte, err error) {
	msg, err := parseMessage(in)
	if err != nil {
		return nil, err
	}
	if msg.getDirection() != s.inDirection() {
		panic("session is wrong direction for message")
	}
	s.mu.Lock()
	res := s.state.upward(msg)
	s.changeState(res.Next)
	s.lastRecv = time.Now()
	s.mu.Unlock()
	for _, resp := range res.Resps {
		resp.setDirection(s.outDirection())
		if err := s.send(ctx, resp); err != nil {
			return nil, err
		}
	}
	if res.Err != nil {
		return nil, res.Err
	}
	return res.Up, nil
}

func (s *session) downward(ctx context.Context, in []byte) error {
	s.mu.Lock()
	res := s.state.downward(in)
	s.changeState(res.Next)
	s.mu.Unlock()
	if res.Err != nil {
		return res.Err
	}
	res.Down.setDirection(s.outDirection())
	return s.send(ctx, res.Down)
}

func (s *session) changeState(next state) {
	if next == nil {
		panic("nil state")
	}
	prev := s.state
	if prev != next && isChanOpen(s.handshakeDone) {
		switch x := next.(type) {
		case *readyState:
			s.completeHandshake(x.remotePublicKey)
		case *endState:
			s.completeHandshake(nil)
		}
	}
	s.state = next
}

// tell waits for the handshake to complete if it hasn't and then sends data over fn
func (s *session) tell(ctx context.Context, ptext []byte) error {
	if err := s.waitReady(ctx); err != nil {
		return err
	}
	return s.downward(ctx, ptext)
}

// completeHandshake must be called with mu
func (s *session) completeHandshake(remotePublicKey p2p.PublicKey) {
	if remotePublicKey == nil {
		panic(remotePublicKey)
	}
	s.remotePublicKey = remotePublicKey
	s.lastRecv = time.Now()
	close(s.handshakeDone)
}

func (s *session) waitReady(ctx context.Context) error {
	// this is necessary to ensure we can return a public key from memory
	// when a cancelled context is passed in, as is required by p2p.LookupPublicKeyInHandler
	if !isChanOpen(s.handshakeDone) {
		return s.error()
	}
	ctx, cf := context.WithTimeout(ctx, HandshakeTimeout)
	defer cf()
	select {
	case <-ctx.Done():
		return &ErrHandshake{
			Message: "timed out waiting for handshake to complete",
			Cause:   ctx.Err(),
		}
	case <-s.handshakeDone:
		return s.waitReady(ctx)
	}
}

func (s *session) error() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if st, ok := s.state.(*endState); ok {
		return st.err
	}
	return nil
}

func (s *session) isExpired(now time.Time) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	sessionAge := now.Sub(s.createdAt)
	recvAge := now.Sub(s.lastRecv)
	return sessionAge > MaxSessionLife || recvAge > SessionIdleTimeout
}

func (s *session) isErrored() bool {
	return s.error() != nil
}

func (s *session) isInitiator() bool {
	return s.initiator
}

func (s *session) getRemotePeerID() p2p.PeerID {
	return p2p.NewPeerID(s.getRemotePublicKey())
}

func (s *session) getRemotePublicKey() p2p.PublicKey {
	if isChanOpen(s.handshakeDone) {
		panic("getRemotePublicKey called before handshake has completed")
	}
	if s.remotePublicKey == nil {
		panic("remotePublicKey cannot be nil")
	}
	return s.remotePublicKey
}

func (s *session) outDirection() direction {
	if s.initiator {
		return directionInitToResp
	}
	return directionRespToInit
}

func (s *session) inDirection() direction {
	if s.initiator {
		return directionRespToInit
	}
	return directionInitToResp
}

func isChanOpen(x chan struct{}) bool {
	select {
	case <-x:
		return false
	default:
		return true
	}
}
