package p2pke2

import (
	"errors"
	"io"
	"time"

	"github.com/brendoncarroll/go-tai64"
)

const (
	DefaultActivityTimeout  = 5 * time.Second
	DefaultHandshakeTimeout = 5 * time.Second
	DefaultSessionLifetime  = 120 * time.Second
)

type ChannelStateParams[XOF, KEMPriv, KEMPub, Auth any] struct {
	Suite Suite[XOF, KEMPriv, KEMPub]
	// If a session has not received a message within this duration then it is discarded.
	ActivityTimeout time.Duration
	// If a handshake has been ongoing for longer than this duration then it is discarded.
	HandshakeTimeout time.Duration
	// SessionLifetime is the maximum amount of time a session can be used.
	SessionLifetime time.Duration
	// Entropy is read from Random
	Random io.Reader
	// Called to create a new Authenticator for each session
	NewAuth func() Auth
}

// ChannelState contains all the state for a Channel
// It spawns no background goroutines, and none of its methods block.
// All the memory needed to maintain the secure channel is in this struct.
// You can copy channel state to whereever you want.  There are no pointers.
//
// A ChannelState manages 3 sessions, and is aware of time.
// ChannelState will expire sessions which are too old, or have sent the maximum number of messages.
type ChannelState[XOF, KEMPriv, KEMPub, Auth any] struct {
	params   ChannelStateParams[XOF, KEMPriv, KEMPub, Auth]
	sessions [3]sessionEntry[XOF, KEMPriv, KEMPub]
}

func NewChannelState[XOF, KEMPriv, KEMPub, Auth any](params ChannelStateParams[XOF, KEMPriv, KEMPub, Auth]) ChannelState[XOF, KEMPriv, KEMPub, Auth] {
	if params.ActivityTimeout == 0 {
		params.ActivityTimeout = DefaultActivityTimeout
	}
	if params.HandshakeTimeout == 0 {
		params.HandshakeTimeout = DefaultHandshakeTimeout
	}
	if params.SessionLifetime == 0 {
		params.SessionLifetime = DefaultSessionLifetime
	}
	return ChannelState[XOF, KEMPriv, KEMPub, Auth]{
		params: params,
	}
}

func (c *ChannelState[XOF, KEMPriv, KEMPub, AuthInfo]) Send(out []byte, msg []byte, now Time) ([]byte, error) {
	// Send always sends on the current ready session.
	current := c.getCurrent()
	if !c.isAlive(current, now) {
		return nil, ErrNoReadySession{}
	}
	return nil, ErrNoReadySession{}
}

func (c *ChannelState[XOF, KEMPriv, KEMPub, AuthInfo]) SendHandshake(out []byte, now Time) ([]byte, error) {
	next := c.getNext()
	if next.IsZero() || tai64DeltaGt(now, next.CreatedAt, c.params.HandshakeTimeout) {
		var err error
		next.Clear()
		next.CreatedAt = now
		next.LastReceived = now
		next.Session, err = c.newSession(true)
		if err != nil {
			return nil, err
		}
	}
	if next.Session.IsHandshakeDone() {
		return nil, errors.New("no handshake message to send")
	}
	return next.Session.SendHandshake(out)
}

// Deliver takes an inbound message and processes it and appends any application data to out.
//
// - Deliver returns (nil, non-nil) if there is an error.  The error can be logged, but the channel will recover.
// - Deliver returns (nil, nil) if there is nothing for the application.
// - Deliver returns (out ++ ptext, nil) if there is no error and plaintext for the application.
func (c *ChannelState[XOF, KEMPriv, KEMPub, AuthInfo]) Deliver(out []byte, inbound []byte, now Time) ([]byte, error) {
	// apply to all sessions.
	var lastErr error
	for i, se := range c.sessions {
		if se.IsZero() {
			continue
		}
		out, err := se.Session.Deliver(out, inbound)
		if err == nil {
			if i == 0 && se.Session.IsReady() {
				c.sessions[2], c.sessions[1] = c.sessions[1], c.sessions[0]
				c.sessions[0].Clear()
			}
			return out, nil
		}
		lastErr = err
	}
	if !IsInitHello(inbound) {
		return nil, lastErr
	}
	// if no match and InitHello then create a new one.
	next := c.getNext()
	next.Clear()
	next.CreatedAt = now
	next.LastReceived = now
	var err error
	next.Session, err = c.newSession(false)
	return nil, err
}

func (c *ChannelState[XOF, KEMPriv, KEMPub, Auth]) Timer() time.Duration {
	return 0
}

func (c *ChannelState[XOF, KEMPriv, KEMPub, Auth]) LastRecv() (ret Time) {
	for _, s := range c.sessions {
		if s.IsZero() {
			continue
		}
		t := s.LastReceived
		if t.After(ret) {
			ret = t
		}
	}
	return ret
}

func (c *ChannelState[XOF, KEMPriv, KEMPub, Auth]) newSession(isInit bool) (ret Session[XOF, KEMPriv, KEMPub], _ error) {
	var seed [32]byte
	if _, err := io.ReadFull(c.params.Random, seed[:]); err != nil {
		return ret, err
	}
	return NewSession(SessionParams[XOF, KEMPriv, KEMPub]{
		Suite:  c.params.Suite,
		IsInit: isInit,
		Seed:   &seed,
	}), nil
}

func (c *ChannelState[XOF, KEMPriv, KEMPub, Auth]) isAlive(se *sessionEntry[XOF, KEMPriv, KEMPub], now Time) bool {
	return !se.IsZero() &&
		tai64DeltaLt(now, se.LastReceived, c.params.ActivityTimeout) &&
		tai64DeltaLt(now, se.CreatedAt, c.params.SessionLifetime)
}

func (c *ChannelState[XOF, KEMPriv, KEMPub, Auth]) getNext() *sessionEntry[XOF, KEMPriv, KEMPub] {
	return &c.sessions[0]
}

func (c *ChannelState[XOF, KEMPriv, KEMPub, Auth]) getCurrent() *sessionEntry[XOF, KEMPriv, KEMPub] {
	return &c.sessions[1]
}

type sessionEntry[XOF, KEMPriv, KEMPub any] struct {
	ID           [32]byte
	CreatedAt    Time
	LastReceived Time
	Session      Session[XOF, KEMPriv, KEMPub]
}

func (se *sessionEntry[XOF, KEMPriv, KEMPub]) IsZero() bool {
	return se.ID == ([32]byte{})
}

func (se *sessionEntry[XOF, KEMPriv, KEMPub]) Clear() {
	*se = sessionEntry[XOF, KEMPriv, KEMPub]{}
}

type ErrNoReadySession struct {
}

func (e ErrNoReadySession) Error() string {
	return "no ready session"
}

func IsNoReadySession(x error) bool {
	return errors.As(x, &ErrNoReadySession{})
}

// returns true if a - b > x
func tai64DeltaGt(a, b tai64.TAI64N, x time.Duration) bool {
	d := a.GoTime().UnixNano() - b.GoTime().UnixNano()
	return time.Duration(d) > x
}

// returns true if a - b < x
func tai64DeltaLt(a, b tai64.TAI64N, x time.Duration) bool {
	d := a.GoTime().UnixNano() - b.GoTime().UnixNano()
	return time.Duration(d) < x
}
