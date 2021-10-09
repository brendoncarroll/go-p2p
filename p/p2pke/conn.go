package p2pke

import (
	"context"
	sync "sync"
	"time"

	"github.com/brendoncarroll/go-p2p"
	"golang.org/x/crypto/blake2b"
)

type Conn struct {
	outbound, inbound *halfConn
}

func NewConn(privateKey p2p.PrivateKey) *Conn {
	return &Conn{
		outbound: newHalfConn(SessionParams{
			PrivateKey: privateKey,
			IsInit:     true,
		}),
		inbound: newHalfConn(SessionParams{
			PrivateKey: privateKey,
			IsInit:     false,
		}),
	}
}

func (c *Conn) Send(ctx context.Context, x []byte, send Sender) error {
	hc, err := c.waitReady(ctx, send)
	if err != nil {
		return err
	}
	return hc.Send(ctx, x, send)
}

func (c *Conn) Deliver(ctx context.Context, out, x []byte, send Sender) ([]byte, error) {
	msg, err := ParseMessage(x)
	if err != nil {
		return nil, err
	}
	switch msg.GetDirection() {
	case InitToResp:
		return c.inbound.Deliver(out, x, send)
	case RespToInit:
		return c.outbound.Deliver(out, x, send)
	default:
		panic("invalid direction")
	}
}

func (c *Conn) RemoteKey() p2p.PublicKey {
	pubKey := c.outbound.RemoteKey()
	if pubKey != nil {
		return pubKey
	}
	return c.inbound.RemoteKey()
}

func (c *Conn) waitReady(ctx context.Context, send Sender) (*halfConn, error) {
	c.outbound.mu.Lock()
	c.outbound.s.StartHandshake(send)
	c.outbound.mu.Unlock()
	select {
	case <-c.inbound.readyChan():
		return c.inbound, nil
	case <-c.outbound.readyChan():
		return c.outbound, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

type halfConn struct {
	params SessionParams

	mu          sync.Mutex
	m0Hash      [32]byte
	s           *Session
	closedReady bool
	ready       chan struct{}
}

func newHalfConn(params SessionParams) *halfConn {
	return &halfConn{
		params: params,
		ready:  make(chan struct{}),
	}
}

func (hc *halfConn) Send(ctx context.Context, x []byte, send Sender) error {
	hc.mu.Lock()
	defer hc.mu.Unlock()
	hc.start(send)
	return hc.s.Send(x, time.Now(), send)
}

func (hc *halfConn) Deliver(out, x []byte, send Sender) ([]byte, error) {
	hc.mu.Lock()
	defer hc.mu.Unlock()
	if hc.params.IsInit && IsInitHello(x) {
		msgHash := blake2b.Sum256(x)
		if msgHash != hc.m0Hash {
			hc.reset(msgHash)
		}
	}
	out, err := hc.s.Deliver(out, x, time.Now(), send)
	if err != nil {
		return nil, err
	}
	if hc.s.IsReady() && !hc.closedReady {
		close(hc.ready)
		hc.closedReady = true
	}
	return out, nil
}

func (hc *halfConn) RemoteKey() p2p.PublicKey {
	hc.mu.Lock()
	defer hc.mu.Unlock()
	return hc.s.RemoteKey()
}

func (hc *halfConn) readyChan() chan struct{} {
	hc.mu.Lock()
	defer hc.mu.Unlock()
	if hc.s == nil {
		params := hc.params
		params.Now = time.Now()
		hc.s = NewSession(params)
	}
	return hc.ready
}

func (hc *halfConn) reset(m0Hash [32]byte) {
	hc.m0Hash = m0Hash
	if !hc.closedReady {
		close(hc.ready)
	}
	hc.closedReady = false
	hc.ready = make(chan struct{})
	params := hc.params
	params.Now = time.Now()
	hc.s = NewSession(params)
}

func (hc *halfConn) start(send Sender) {
	if !hc.s.IsReady() {
		hc.s.StartHandshake(send)
	}
}
