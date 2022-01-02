package p2pke

import (
	"context"
	sync "sync"
	"time"

	"github.com/brendoncarroll/go-p2p"
	"github.com/pkg/errors"
	"golang.org/x/crypto/blake2b"
)

type Channel struct {
	privateKey        p2p.PrivateKey
	outbound, inbound *halfChannel
	keyCell           *keyCell
}

func NewChannel(privateKey p2p.PrivateKey, checkKey func(p2p.PublicKey) error) *Channel {
	if checkKey == nil {
		checkKey = func(p2p.PublicKey) error { return nil }
	}
	kc := &keyCell{checkKey: checkKey}
	c := &Channel{
		privateKey: privateKey,
		outbound: newHalfChannel(SessionParams{
			PrivateKey: privateKey,
			IsInit:     true,
		}, kc.SetKey),
		inbound: newHalfChannel(SessionParams{
			PrivateKey: privateKey,
			IsInit:     false,
		}, kc.SetKey),
		keyCell: kc,
	}
	return c
}

// Send will call send with an encrypted message containing x
// It may also send a handshake message.
// Send will be called multiple times if a handshake has to be performed.
func (c *Channel) Send(ctx context.Context, x []byte, send Sender) error {
	hc, err := c.waitReady(ctx, send)
	if err != nil {
		return err
	}
	return hc.Send(ctx, x, send)
}

// Deliver decrypts the payload in x if it contains application data, and appends it to out.
// if err != nil, then an error occured.  The Channel is capable of recovering.
// if out != nil, then it is application data.
// if out == nil, then the message was either invalid or contained a handshake message
// and there is nothing more for the caller to do.
func (c *Channel) Deliver(ctx context.Context, out, x []byte, send Sender) ([]byte, error) {
	msg, err := ParseMessage(x)
	if err != nil {
		return nil, err
	}
	switch msg.GetDirection() {
	case InitToResp:
		out, err = c.inbound.Deliver(ctx, out, x, send)
	case RespToInit:
		out, err = c.outbound.Deliver(ctx, out, x, send)
	default:
		panic("invalid direction")
	}
	return out, err
}

// LocalKey returns the public key used by the local party to authenticate.
// It will correspond to the private key passed to NewChannel.
func (c *Channel) LocalKey() p2p.PublicKey {
	return c.privateKey.Public()
}

// RemoteKey returns the public key used by the remote party to authenticate.
// It can be nil, if there has been no successful handshake.
func (c *Channel) RemoteKey() p2p.PublicKey {
	return c.keyCell.GetKey()
}

// LastReceived returns the time that a message was received
func (c *Channel) LastReceived() time.Time {
	return latestTime(c.inbound.LastReceived(), c.outbound.LastReceived())
}

// LastSent returns the time that a message was last sent
func (c *Channel) LastSent() time.Time {
	return latestTime(c.inbound.LastSent(), c.outbound.LastSent())
}

// WaitReady blocks until the either an inbound or outbound session
// has been established.
// send is called to send handshake messages.
func (c *Channel) WaitReady(ctx context.Context, send Sender) error {
	_, err := c.waitReady(ctx, send)
	return err
}

func (c *Channel) waitReady(ctx context.Context, send Sender) (*halfChannel, error) {
	inbound := c.inbound.ReadyChan()
	outbound := c.outbound.ReadyChan()
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		c.outbound.InitHandshake(send)
		select {
		case <-ticker.C:
			// continue
		case <-inbound:
			return c.inbound, nil
		case <-outbound:
			return c.outbound, nil
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
}

type halfChannel struct {
	params SessionParams
	setKey func(p2p.PublicKey) error

	mu          sync.Mutex
	m0Hash      [32]byte
	initMessage []byte

	s           *Session
	closedReady bool
	ready       chan struct{}

	lastReceived, lastSent time.Time
}

func newHalfChannel(params SessionParams, setKey func(p2p.PublicKey) error) *halfChannel {
	hc := &halfChannel{
		params: params,
		ready:  make(chan struct{}),
		setKey: setKey,
	}
	hc.s = NewSession(hc.getParams())
	return hc
}

// Send waits until the halfChannel is ready, then creates an encrypted message for x
// and calls send.
func (hc *halfChannel) Send(ctx context.Context, x []byte, send Sender) error {
	hc.mu.Lock()
	ready := hc.ready
	hc.mu.Unlock()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-ready:
		hc.mu.Lock()
		out, err := hc.s.Send(nil, x, time.Now())
		hc.lastSent = time.Now()
		hc.mu.Unlock()
		if err != nil {
			return err
		}
		send(out)
		return nil
	}
}

func (hc *halfChannel) Deliver(ctx context.Context, out, x []byte, send Sender) ([]byte, error) {
	// check if this could be an early arriving postHandshake message
	// and give an oppurtunity for the handshake message to get there first.
	// In practice this makes the tests less flaky, but there might be a better way to handle this.
	// Once the connection is established, this won't happen.
	// It might also be worth limiting the number of these messages that we are delaying.
	if !hc.IsReady() && IsPostHandshake(x) {
		timer := time.NewTimer(200 * time.Millisecond)
		defer timer.Stop()
		select {
		case <-timer.C:
		case <-hc.ReadyChan():
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	var isApp bool
	var closeReady chan struct{}
	if err := func() error {
		hc.mu.Lock()
		defer hc.mu.Unlock()
		if !hc.params.IsInit && IsInitHello(x) {
			msgHash := blake2b.Sum256(x)
			if msgHash == hc.m0Hash {
				return nil
			}
			hc.reset(msgHash)
		}
		var err error
		isApp, out, err = hc.s.Deliver(out, x, time.Now())
		if err != nil {
			return err
		}
		hc.lastReceived = time.Now()
		// if the session just became ready then close the ready channel
		if hc.s.IsReady() && !hc.closedReady {
			// check and set the remote key
			if err := hc.setKey(hc.s.RemoteKey()); err != nil {
				hc.reset([32]byte{})
				return errors.Errorf("keys do not match")
			}
			// if we need to send anything, don't mark it ready until it has been sent.
			if len(out) > 0 {
				closeReady = hc.ready
			} else {
				close(hc.ready)
				hc.closedReady = true
			}
		}
		return nil
	}(); err != nil {
		return nil, err
	}
	if isApp {
		return out, nil
	} else if len(out) > 0 {
		send(out)
	}
	// after the send we can now close the ready channel
	if closeReady != nil {
		hc.mu.Lock()
		if closeReady == hc.ready && !hc.closedReady {
			close(hc.ready)
			hc.closedReady = true
		}
		hc.mu.Unlock()
	}
	return nil, nil
}

func (hc *halfChannel) ReadyChan() <-chan struct{} {
	hc.mu.Lock()
	defer hc.mu.Unlock()
	return hc.ready
}

func (hc *halfChannel) LastReceived() time.Time {
	return hc.lastReceived
}

func (hc *halfChannel) LastSent() time.Time {
	return hc.lastSent
}

func (hc *halfChannel) IsReady() bool {
	hc.mu.Lock()
	defer hc.mu.Unlock()
	return hc.closedReady
}

func (hc *halfChannel) getParams() SessionParams {
	params := hc.params
	params.Now = time.Now()
	return params
}

func (hc *halfChannel) reset(m0Hash [32]byte) {
	hc.m0Hash = m0Hash
	if hc.closedReady {
		hc.closedReady = false
		hc.ready = make(chan struct{})
	}
	params := hc.params
	params.Now = time.Now()
	hc.s = NewSession(params)
	hc.initMessage = nil
}

func (hc *halfChannel) InitHandshake(send Sender) {
	if !hc.params.IsInit {
		panic("InitHandshake called on non-initiator session")
	}
	var data []byte
	func() {
		hc.mu.Lock()
		defer hc.mu.Unlock()
		if hc.s.IsReady() {
			return
		}
		if hc.initMessage == nil {
			hc.initMessage = hc.s.StartHandshake(nil)
		}
		data = hc.initMessage
	}()
	if data != nil {
		send(data)
	}
}

// keyCell holds a public key.
type keyCell struct {
	checkKey func(p2p.PublicKey) error

	mu        sync.Mutex
	publicKey p2p.PublicKey
}

func (kc *keyCell) SetKey(x p2p.PublicKey) error {
	if err := kc.checkKey(x); err != nil {
		return err
	}
	kc.mu.Lock()
	defer kc.mu.Unlock()
	if kc.publicKey != nil {
		if !p2p.EqualPublicKeys(x, kc.publicKey) {
			return errors.Errorf("keys do not match %v %v", kc.publicKey, x)
		}
	}
	kc.publicKey = x
	return nil
}

func (kc *keyCell) GetKey() p2p.PublicKey {
	kc.mu.Lock()
	defer kc.mu.Unlock()
	return kc.publicKey
}

func latestTime(a, b time.Time) time.Time {
	if b.After(a) {
		return b
	}
	return a
}
