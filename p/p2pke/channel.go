package p2pke

import (
	"bytes"
	"context"
	"io"
	sync "sync"
	"time"

	"github.com/brendoncarroll/go-p2p"
	"github.com/brendoncarroll/go-tai64"
	"github.com/pkg/errors"
	"golang.org/x/crypto/blake2b"
	"golang.org/x/exp/slog"
)

// SendFunc is the type of functions called to send messages by the channel.
type SendFunc func([]byte)

type ChannelConfig struct {
	// PrivateKey is the signing key used to prove identity to the other party in the channel.
	// *REQUIRED*
	PrivateKey p2p.PrivateKey
	// Send is used to send p2pke protocol messages including ciphertexts and handshake messages.
	// *REQUIRED*
	Send SendFunc
	// AcceptKey is used to check if a key is allowed before connecting
	// *REQUIRED*.
	AcceptKey func(p2p.PublicKey) bool
	// Logger is used for logging, nil disables logs.
	Logger *slog.Logger

	// KeepAliveTimeout is the amount of time to consider a session alive wihtout receiving a message
	// through it.
	KeepAliveTimeout time.Duration
	// HandshakeBackoff is the amount of time to wait between sending handshake messages.
	HandshakeBackoff time.Duration
	// RekeyAfterTime is the amount of time between rekeying a session.
	RekeyAfterTime time.Duration
	// RejectAfterTime is the duration after session creation when the session will send and
	// received messages.
	RejectAfterTime time.Duration
}

type Channel struct {
	params ChannelConfig
	log    *slog.Logger

	mu sync.RWMutex
	// sessions holds the 3 sessions: previous, current, next
	// previous and current are always ready s.IsReady() == true, next is always not ready s.IsReady() == false.
	// Once next becomes ready it immediately becomes current, the old current becomes previous, and the old previous is discarded.
	sessions        [3]sessionEntry
	remoteKey       p2p.PublicKey
	remoteTimestamp tai64.TAI64N
	// ready is closed, and reset whenever the current session changes.
	ready chan struct{}
	// lastReceived is the last time we received a message through the current session.
	lastReceived time.Time
	// lastSent is the las time we sent a message through any session.
	lastSent time.Time

	rekeyTimer     *Timer
	handshakeTimer *Timer
}

func NewChannel(params ChannelConfig) *Channel {
	if params.PrivateKey == nil {
		panic("PrivateKey must be set")
	}
	if params.Send == nil {
		panic("Send must be set")
	}
	if params.AcceptKey == nil {
		panic("AcceptKey must be set")
	}
	if params.Logger == nil {
		nullLogger := slog.New(slog.NewTextHandler(io.Discard))
		params.Logger = &nullLogger
	}
	if params.KeepAliveTimeout == 0 {
		params.KeepAliveTimeout = KeepAliveTimeout
	}
	if params.HandshakeBackoff == 0 {
		params.HandshakeBackoff = HandshakeBackoff
	}
	if params.RekeyAfterTime == 0 {
		params.RekeyAfterTime = RekeyAfterTime
	}
	if params.RejectAfterTime == 0 {
		params.RejectAfterTime = RejectAfterTime
	}
	c := &Channel{
		params: params,
		log:    params.Logger,
		ready:  make(chan struct{}),
	}
	c.rekeyTimer = newTimer(c.onRekey)
	c.handshakeTimer = newTimer(c.onHandshake)
	return c
}

// Send will send an encrypted message containing x
// It may also send a handshake message.
// Send blocks until a Session has been established and the message can be sent or the context is cancelled.
func (c *Channel) Send(ctx context.Context, x p2p.IOVec) error {
	s, err := c.getOrInit(ctx)
	if err != nil {
		return err
	}
	return c.doThenSend(func() ([]byte, error) {
		now := time.Now()
		return s.Send(nil, p2p.VecBytes(nil, x), now)
	})
}

// Deliver decrypts the payload in x if it contains application data, and appends it to out.
// if err != nil, then an error occured.  The Channel is capable of recovering.
// if out != nil, then it is application data.
// if out == nil, then the message was either invalid or contained a handshake message
// and there is nothing more for the caller to do.
//
// e.g.
// out, err := c.Deliver(nil, input)
//
//	if err != nil {
//	  // handle the error
//	} else if out != nil {
//
//	  // deliver application data
//	} else {
//
//	  // nothing to do
//	}
func (c *Channel) Deliver(out, x []byte) ([]byte, error) {
	now := time.Now()
	var appData []byte
	if err := c.doThenSend(func() ([]byte, error) {
		for i, se := range c.sessions {
			s := se.Session
			if s == nil {
				continue
			}
			readyBefore := s.IsReady()
			isApp, out, err := s.Deliver(out, x, now)
			if err != nil {
				continue
			}
			if isApp {
				appData = out
				return nil, nil
			}
			// if the session became ready, then make it the current and notify.
			if !readyBefore && s.IsReady() {
				if i != 2 {
					panic(i)
				}
				if err := c.onReadySession(now); err != nil {
					return nil, err
				}
			}
			if len(out) == 0 {
				continue
			}
			return out, nil
		}
		// The message did not match a session so now check if we can create a new session.
		if !IsInitHello(x) {
			return nil, errors.New("message did not match a session")
		}
		sid := blake2b.Sum256(x)
		for _, se := range c.sessions {
			if se.ID == sid {
				// repeated InitHello, nothing to do.
				return nil, nil
			}
		}
		// create new session
		newS, err := c.newResp(x, c.remoteTimestamp)
		if err != nil {
			return nil, err
		}
		s := c.proposeNewSession(sid, newS)
		return s.Handshake(nil), nil
	}); err != nil {
		if c.isFatal(err) {
			return nil, err
		}
		return nil, nil
	}
	return appData, nil
}

// Close releases all resources associated with the channel.
// send will not be called after Close completes.
func (c *Channel) Close() error {
	for _, t := range []*Timer{c.rekeyTimer, c.handshakeTimer} {
		t.StopSync()
	}
	return nil
}

// LocalKey returns the public key used by the local party to authenticate.
// It will correspond to the private key passed to NewChannel.
func (c *Channel) LocalKey() p2p.PublicKey {
	return c.params.PrivateKey.Public()
}

// RemoteKey returns the public key used by the remote party to authenticate.
// It can be nil, if there has been no successful handshake.
func (c *Channel) RemoteKey() p2p.PublicKey {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.remoteKey
}

// LastReceived returns the time that a message was received
func (c *Channel) LastReceived() time.Time {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.lastReceived
}

// LastSent returns the time that a message was last sent
func (c *Channel) LastSent() time.Time {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.lastSent
}

// WaitReady blocks until a session has been established.
// It will initiate a session if none exists.
// After WaitReady returns: RemoteKey() != nil
func (c *Channel) WaitReady(ctx context.Context) error {
	_, err := c.getOrInit(ctx)
	return err
}

// newInit creates a new session as the initiator.
func (c *Channel) newInit(now time.Time) ([32]byte, *Session) {
	s := NewSession(SessionConfig{
		PrivateKey:  c.params.PrivateKey,
		IsInit:      true,
		Logger:      c.params.Logger,
		Now:         now,
		RejectAfter: c.params.RejectAfterTime,
	})
	out := s.Handshake(nil)
	id := blake2b.Sum256(out)
	return id, s
}

// newResp creates a new session as the responder
// it ensures that the public key is valid and matches any existing public keys we have seen.
func (c *Channel) newResp(m0 []byte, minTime tai64.TAI64N) (*Session, error) {
	msg, err := ParseMessage(m0)
	if err != nil {
		return nil, err
	}
	initHello, err := msg.GetInitHello()
	if err != nil {
		return nil, err
	}
	helloTime, err := tai64.ParseN(initHello.TimestampTai64N)
	if err != nil {
		return nil, err
	}
	if helloTime.Before(minTime) {
		return nil, errors.New("timestamp too early to consider session")
	}
	pubKey, err := verifyAuthClaim(purposeTimestamp, initHello.KeyX509, initHello.TimestampTai64N, initHello.Sig)
	if err != nil {
		return nil, err
	}
	if err := c.checkKey(pubKey); err != nil {
		return nil, err
	}
	now := time.Now()
	s := NewSession(SessionConfig{
		PrivateKey:  c.params.PrivateKey,
		IsInit:      false,
		Logger:      c.log,
		Now:         now,
		RejectAfter: c.params.RejectAfterTime,
	})
	_, _, err = s.Deliver(nil, m0, now)
	if err != nil {
		return nil, err
	}
	return s, nil
}

// proposeNextSession proposes a session created from a new message
// and checks to see if it should become the new prospective session, possibly
// replacing an existing prospective session.
func (c *Channel) proposeNewSession(sid [32]byte, newS *Session) (ret *Session) {
	if s := c.sessions[2].Session; s != nil && bytes.Compare(c.sessions[2].ID[:], sid[:]) < 0 {
		c.log.Debug("not replacing prospective session")
		return s
	} else if s != nil {
		c.log.Debug("replacing prospective session", slog.Any("old", s), slog.Any("new", newS))
		ret = newS
	} else {
		c.log.Debug("creating new session", slog.Any("new", newS))
		ret = newS
	}
	c.setNext(sessionEntry{
		ID:      sid,
		Session: newS,
	})
	if ret.IsInit() {
		c.rekeyTimer.Reset(c.params.RekeyAfterTime)
	}
	return ret
}

// onReadySession is called when the prospective session becomes ready
func (c *Channel) onReadySession(now time.Time) error {
	se := c.sessions[2]
	if c.remoteKey != nil && !p2p.EqualPublicKeys(c.remoteKey, se.Session.RemoteKey()) {
		c.setNext(sessionEntry{})
		return errors.New("session negotiated with wrong peer")
	}
	c.remoteKey = se.Session.RemoteKey()
	c.lastReceived = now
	c.remoteTimestamp = se.Session.InitHelloTime()
	c.setCurrent(se)
	c.setNext(sessionEntry{})
	if se.Session.isInit {
		// if we were the initiator, we are responsible for rekeying
		c.rekeyTimer.Reset(c.params.RekeyAfterTime)
	}
	select {
	case <-c.ready:
	default:
		close(c.ready)
	}
	return nil
}

// setCurrent sets the current session, and moves the current session to the previous session.
func (c *Channel) setCurrent(x sessionEntry) {
	c.sessions[0] = c.sessions[1]
	c.sessions[1] = x
}

func (c *Channel) setNext(x sessionEntry) {
	c.sessions[2] = x
}

func (c *Channel) checkKey(pubKey p2p.PublicKey) error {
	if c.remoteKey != nil && p2p.EqualPublicKeys(c.remoteKey, pubKey) {
		return nil
	} else if c.params.AcceptKey(pubKey) {
		return nil
	}
	return errors.New("key rejected")
}

func (c *Channel) expireSessions(now time.Time) {
	// expire the previous session only if it is expired
	if s := c.sessions[0].Session; s != nil && s.ExpiresAt().Before(now) {
		c.log.Debug("expiring previous session")
		c.sessions[0] = sessionEntry{}
	}
	// expire the current session if it is expired or we have not received a packet recently.
	if s := c.sessions[1].Session; s != nil && (s.ExpiresAt().Before(now) || now.Sub(c.lastReceived) > c.params.KeepAliveTimeout) {
		c.log.Debug("expiring current session")
		c.sessions[0] = c.sessions[1]
		c.sessions[1] = sessionEntry{}
		select {
		case <-c.ready:
		default:
			close(c.ready)
		}
		c.ready = make(chan struct{})
	}
	// expire the prospective session only if it is expired.
	if s := c.sessions[2].Session; s != nil && s.ExpiresAt().Before(now) {
		c.log.Debug("expiring prospective session")
		c.sessions[2] = sessionEntry{}
	}
}

func (c *Channel) getOrInit(ctx context.Context) (*Session, error) {
	for {
		c.mu.Lock()
		now := time.Now()
		c.expireSessions(now)
		if s := c.sessions[1].Session; s != nil {
			c.mu.Unlock()
			return s, nil
		}
		if s := c.sessions[2].Session; s == nil {
			c.rekeyTimer.Reset(0)
		}
		ready := c.ready
		c.mu.Unlock()

		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-ready:
			c.mu.Lock()
			se := c.sessions[1]
			if se.Session != nil && se.Session.IsReady() {
				c.mu.Unlock()
				return se.Session, nil
			}
			c.mu.Unlock()
		}
	}
}

// onRekey is called by rekeyTimer
func (c *Channel) onRekey() {
	c.doThenSend(func() ([]byte, error) {
		now := time.Now()
		c.expireSessions(now)
		if c.sessions[2].Session == nil {
			id, s := c.newInit(now)
			c.proposeNewSession(id, s)
			c.handshakeTimer.Reset(0)
		}
		return nil, nil
	})
}

// onHandshake is called by handshakeTimer
// It checks if there are sessions for which we need to perform handshakes.
// And sends handshake messages for them.
func (c *Channel) onHandshake() {
	var toSend [][]byte
	func() {
		c.mu.Lock()
		defer c.mu.Unlock()
		for _, se := range c.sessions {
			if se.Session != nil && !se.Session.IsReady() {
				out := se.Session.Handshake(nil)
				if len(out) > 0 {
					toSend = append(toSend, out)
				}
			}
		}
	}()
	for _, data := range toSend {
		c.params.Send(data)
	}
	// need to wake up to send another handshake message
	if len(toSend) > 0 {
		c.handshakeTimer.Reset(c.params.HandshakeBackoff)
	}
}

func (c *Channel) doThenSend(fn func() ([]byte, error)) error {
	var data []byte
	if err := func() error {
		c.mu.Lock()
		defer c.mu.Unlock()
		var err error
		data, err = fn()
		return err
	}(); err != nil {
		return err
	}
	if data != nil {
		c.params.Send(data)
	}
	return nil
}

func (c *Channel) isFatal(err error) bool {
	return false
}

type sessionEntry struct {
	ID      [32]byte
	Session *Session
}
