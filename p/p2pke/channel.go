package p2pke

import (
	"context"
	sync "sync"
	"time"

	mrand "math/rand"

	"github.com/brendoncarroll/go-p2p"
	"github.com/pkg/errors"
	"golang.org/x/crypto/blake2b"
	"golang.org/x/sync/errgroup"
)

const handshakeSendPeriod = 250 * time.Millisecond

type Channel struct {
	privateKey        p2p.PrivateKey
	send              Sender
	outbound, inbound *halfChannel
	keyCell           *keyCell
	eg                errgroup.Group
}

func NewChannel(privateKey p2p.PrivateKey, allowKey func(p2p.PublicKey) bool, send Sender) *Channel {
	if allowKey == nil {
		allowKey = func(x p2p.PublicKey) bool {
			return true
		}
	}
	kc := &keyCell{checkKey: allowKey}
	c := &Channel{
		privateKey: privateKey,
		send:       send,
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
func (c *Channel) Send(ctx context.Context, x []byte) error {
	hc, err := c.waitReady(ctx)
	if err != nil {
		return err
	}
	return hc.Send(ctx, x, c.send)
}

// Deliver decrypts the payload in x if it contains application data, and appends it to out.
// if err != nil, then an error occured.  The Channel is capable of recovering.
// if out != nil, then it is application data.
// if out == nil, then the message was either invalid or contained a handshake message
// and there is nothing more for the caller to do.
func (c *Channel) Deliver(ctx context.Context, out, x []byte) ([]byte, error) {
	msg, err := ParseMessage(x)
	if err != nil {
		return nil, err
	}
	switch msg.GetDirection() {
	case InitToResp:
		out, err = c.inbound.Deliver(ctx, out, x, c.send)
	case RespToInit:
		out, err = c.outbound.Deliver(ctx, out, x, c.send)
	default:
		panic("invalid direction")
	}
	return out, err
}

// Close releases all resources associated with the channel.
// send will not be called after Close completes
func (c *Channel) Close() error {
	c.send = func([]byte) {}
	return nil
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
func (c *Channel) WaitReady(ctx context.Context) error {
	_, err := c.waitReady(ctx)
	return err
}

// waitReady sends handshakes in a loop on the output channel
// and waits for any channel to be ready.
func (c *Channel) waitReady(ctx context.Context) (*halfChannel, error) {
	if c.inbound.IsReady() && c.outbound.IsReady() {
		if mrand.Intn(2) > 0 {
			return c.inbound, nil
		} else {
			return c.outbound, nil
		}
	}
	inbound := c.inbound.ReadyChan()
	outbound := c.outbound.ReadyChan()
	ticker := time.NewTicker(handshakeSendPeriod)
	defer ticker.Stop()
	for {
		c.outbound.InitHandshake(c.send)
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
	queued      []byte

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
	var haveAppData bool
	if err := hc.doThenSend(send, func() ([]byte, error) {
		// check if this could be an early arriving postHandshake message
		// and give an oppurtunity for the handshake message to get there first.
		// In practice this makes the tests less flaky, but there might be a better way to handle this.
		// Once the connection is established, this won't happen.
		// It might also be worth limiting the number of these messages that we are delaying.
		if !hc.s.IsReady() && IsPostHandshake(x) {
			hc.queued = append([]byte{}, x...)
			return nil, nil
		}
		if !hc.params.IsInit && IsInitHello(x) {
			msgHash := blake2b.Sum256(x)
			if msgHash == hc.m0Hash {
				return nil, nil
			}
			hc.reset(msgHash)
		}
		var err error
		haveAppData, out, err = hc.s.Deliver(out, x, time.Now())
		if err != nil {
			return nil, err
		}
		hc.lastReceived = time.Now()
		// if the session just became ready then close the ready channel
		if hc.s.IsReady() && !hc.closedReady {
			// check and set the remote key
			if err := hc.setKey(hc.s.RemoteKey()); err != nil {
				hc.reset([32]byte{})
				return nil, err
			}
			close(hc.ready)
			hc.closedReady = true
		}
		// if there is not app data, then we need to send the response
		if !haveAppData {
			return out, nil
		}
		return nil, nil
	}); err != nil {
		return nil, err
	}
	if haveAppData {
		return out, nil
	}
	hc.mu.Lock()
	queued := hc.queued
	hc.queued = nil
	hc.mu.Unlock()
	if queued != nil {
		return hc.Deliver(ctx, out, queued, send)
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
	hc.doThenSend(send, func() ([]byte, error) {
		if hc.s.IsReady() {
			return nil, nil
		}
		if hc.initMessage == nil {
			hc.initMessage = hc.s.Handshake(nil)
		}
		return hc.initMessage, nil
	})
}

func (hc *halfChannel) doThenSend(send Sender, fn func() ([]byte, error)) error {
	var data []byte
	var err error
	func() {
		hc.mu.Lock()
		defer hc.mu.Unlock()
		data, err = fn()
	}()
	if err != nil {
		return err
	}
	if data != nil {
		send(data)
	}
	return nil
}

// keyCell holds a public key.
type keyCell struct {
	checkKey func(p2p.PublicKey) bool

	mu        sync.Mutex
	publicKey p2p.PublicKey
}

func (kc *keyCell) SetKey(x p2p.PublicKey) error {
	if ok := kc.checkKey(x); !ok {
		return errors.New("key rejected")
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
