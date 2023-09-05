package p2pke2

import (
	"bytes"
	"errors"
	"time"

	"golang.org/x/crypto/sha3"

	"github.com/brendoncarroll/go-tai64"
)

const (
	DefaultActivityTimeout  = 5 * time.Second
	DefaultHandshakeTimeout = 10 * time.Second
	DefaultSessionLifetime  = 120 * time.Second
)

// SessionAPI is used by ChannelState to manipulate sessions.
type SessionAPI interface {
	SendHandshake(out []byte) ([]byte, error)
	Send(out, msg []byte) ([]byte, error)
	Deliver(out, msg []byte) ([]byte, error)
	IsHandshakeDone() bool
	IsInitiator() bool
	IsExhausted() bool
}

type ChannelStateParams[S any] struct {
	// Accept is called for InitHello messages.  If it returns false the message is dropped, and no handshake is attempted.
	Accept func([]byte) bool
	// Reset is called to initialize a Session. isInit == true if the session is the initiator in the handshake.
	Reset func(x *S, isInit bool)
	// API is called with a pointer to the session state.
	API func(*S) SessionAPI

	// If a session has not received a message within this duration then it is discarded.
	ActivityTimeout time.Duration
	// If a handshake has been ongoing for longer than this duration then the session is discarded.
	HandshakeTimeout time.Duration
	// SessionLifetime is the maximum amount of time a session can be used.
	SessionLifetime time.Duration
}

// ChannelState contains all the state for a Channel
// It spawns no background goroutines, and none of its methods block.
// All the memory needed to maintain the secure channel is in this struct.
// You can copy channel state to whereever you want.  There are no pointers.
//
// A ChannelState manages 3 sessions, and is aware of time.
// ChannelState will expire sessions which are too old, or have sent the maximum number of messages.
type ChannelState[S any] struct {
	params   ChannelStateParams[S]
	sessions [3]sessionEntry[S]
	offset   uint8
}

func NewChannelState[S any](params ChannelStateParams[S]) ChannelState[S] {
	if params.Accept == nil {
		params.Accept = func([]byte) bool { return true }
	}
	if params.API == nil {
		panic("API must be set")
	}
	if params.Reset == nil {
		panic("Reset must be set")
	}
	if params.ActivityTimeout == 0 {
		params.ActivityTimeout = DefaultActivityTimeout
	}
	if params.HandshakeTimeout == 0 {
		params.HandshakeTimeout = DefaultHandshakeTimeout
	}
	if params.SessionLifetime == 0 {
		params.SessionLifetime = DefaultSessionLifetime
	}
	return ChannelState[S]{
		params: params,
	}
}

// Send checks if the current session is ready and uses it to append an encrypted version of msg to out
// If there is no ready session Send returns ErrNoReadySession; the caller should use SendHandshake to establish
// a secure Session.
func (c *ChannelState[S]) Send(out []byte, now Time, msg []byte) ([]byte, error) {
	c.expireSessions(now)
	// Send always sends on the current ready session.
	current := c.getCurrent()
	sess := c.getSession(current)
	if !sess.IsHandshakeDone() {
		return nil, ErrNoReadySession{}
	}
	return sess.Send(out, msg)
}

func (c *ChannelState[S]) SendHandshake(out []byte, now Time) ([]byte, error) {
	c.expireSessions(now)
	next := c.getNext()
	sess := c.getSession(next)
	if next.IsZero() {
		next.Clear()
		next.CreatedAt = now
		next.LastReceived = now
		c.params.Reset(&next.Session, true)
		initLen := len(out)
		out, err := sess.SendHandshake(out)
		if err != nil {
			return nil, err
		}
		next.ID = sha3.Sum256(out[initLen:])
		return out, nil
	}
	return sess.SendHandshake(out)
}

// Deliver takes an inbound message and processes it and appends any application data to out.
//
// - Deliver returns (nil, non-nil) if there is an error.  The error can be logged, but the channel will recover.
// - Deliver returns (nil, nil) if there is nothing for the application.
// - Deliver returns (out ++ ptext, nil) if there is no error and plaintext for the application.
func (c *ChannelState[S]) Deliver(out []byte, now Time, inbound []byte) ([]byte, error) {
	c.expireSessions(now)
	// apply to all sessions.
	var lastErr error
	for i := range c.sessions {
		se := &c.sessions[(i+int(c.offset))%len(c.sessions)]
		if se.IsZero() {
			continue
		}
		sess := c.getSession(se)
		out, err := sess.Deliver(out, inbound)
		lastErr = err
		if err == nil {
			se.LastReceived = now
			if se == c.getNext() && sess.IsHandshakeDone() {
				c.promoteNext()
			}
			return out, nil
		}
	}
	if !IsInitHello(inbound) {
		// If it's not InitHello return
		return nil, lastErr
	}
	next := c.getNext()
	sess := c.getSession(next)
	newID := sha3.Sum256(inbound)
	if next.ID == newID {
		// If it matches the current session, then ignore.
		return nil, nil
	}
	if sess.IsInitiator() && bytes.Compare(next.ID[:], newID[:]) < 0 {
		// If we are initiating a handshake and our ID is less than the incoming ID, then ignore.
		// The other side will adopt our session
		return nil, nil
	}
	// if no match and InitHello then create a new one.
	next.Clear()
	next.ID = sha3.Sum256(inbound)
	next.CreatedAt = now
	next.LastReceived = now
	c.params.Reset(&next.Session, false)
	sess = c.getSession(next)
	return sess.Deliver(out, inbound)
}

func (c *ChannelState[S]) IsReady(now Time) bool {
	current := c.getCurrent()
	if current.IsZero() {
		return false
	}
	return c.isReady(current, now)
}

func (c *ChannelState[S]) LastRecv() (ret Time) {
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

// ShouldHandshake returns true if a call to SendHandshake is needed
// If IsReady == false, or if the current session is more than half SessionTimeout old, and we are the initiator
func (c *ChannelState[S]) ShouldHandshake(now Time) bool {
	if !c.IsReady(now) {
		return true
	}
	current := c.getCurrent()
	sess := c.getSession(current)
	return sess.IsInitiator() && tai64DeltaGt(now, current.CreatedAt, c.params.SessionLifetime/2)
}

// expireSessions ensures that any sessions which should be zerod are.
func (c *ChannelState[S]) expireSessions(now Time) {
	for _, se := range c.sessions {
		if se.IsZero() {
			continue
		}
		sess := c.getSession(&se)
		shouldExpire := false
		for _, b := range []bool{
			// Haven't received a message recently.
			tai64DeltaGt(now, se.LastReceived, c.params.ActivityTimeout),
			// Session has been alive too long.
			tai64DeltaGt(now, se.CreatedAt, c.params.SessionLifetime),
			// If the handshake has timed out.
			(!sess.IsHandshakeDone() && tai64DeltaGt(now, se.CreatedAt, c.params.HandshakeTimeout)),
			// session is exhausted
			sess.IsExhausted(),
		} {
			shouldExpire = b || shouldExpire
		}
		if shouldExpire {
			se.Clear()
		}
	}
}

func (c *ChannelState[S]) isReady(se *sessionEntry[S], now Time) bool {
	sess := c.getSession(se)
	return !se.IsZero() && sess.IsHandshakeDone() && !sess.IsExhausted()
}

func (c *ChannelState[S]) getSession(se *sessionEntry[S]) SessionAPI {
	return c.params.API(&se.Session)
}

func (c *ChannelState[S]) getNext() *sessionEntry[S] {
	i := mod(int(c.offset)+0, len(c.sessions))
	return &c.sessions[i]
}

func (c *ChannelState[S]) getCurrent() *sessionEntry[S] {
	i := mod(int(c.offset)+1, len(c.sessions))
	return &c.sessions[i]
}

func (c *ChannelState[S]) getPrev() *sessionEntry[S] {
	i := mod(int(c.offset)+2, len(c.sessions))
	return &c.sessions[i]
}

// promoteNext sets current=next and prev=current.  It clears next.
func (c *ChannelState[S]) promoteNext() {
	c.offset = uint8(mod(int(c.offset)-1, 3))
	c.getNext().Clear()
}

type sessionEntry[S any] struct {
	ID           [32]byte
	CreatedAt    Time
	LastReceived Time
	Session      S
}

func (se *sessionEntry[S]) IsZero() bool {
	return se.ID == ([32]byte{})
}

func (se *sessionEntry[S]) Clear() {
	*se = sessionEntry[S]{}
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

// mod returns x modulo m
func mod(x, m int) int {
	z := x % m
	if z < 0 {
		z += m
	}
	return z
}
