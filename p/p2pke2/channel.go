package p2pke2

import (
	"context"
	"sync"
	"time"

	"github.com/brendoncarroll/go-p2p"
	"github.com/brendoncarroll/go-tai64"
)

type SendFunc = func([]byte)

type ChannelParams[XOF, KEMPriv, KEMPub, Auth any] struct {
	Background context.Context
	Send       SendFunc
	ChannelStateParams[XOF, KEMPriv, KEMPub, Auth]
}

type Channel[Auth any] struct {
	bgCtx      context.Context
	send       SendFunc
	hsInterval time.Duration

	mu    sync.Mutex
	state interface {
		Send(out []byte, msg []byte, now Time) ([]byte, error)
		SendHandshake(out []byte, now Time) ([]byte, error)
		Deliver(out []byte, inbound []byte, now Time) ([]byte, error)
	}
	senderCount int
	cf          context.CancelFunc
	ready       chan struct{}
}

func NewChannel[XOF, KEMPriv, KEMPub, Auth any](params ChannelParams[XOF, KEMPriv, KEMPub, Auth]) *Channel[Auth] {
	cs := NewChannelState[XOF, KEMPriv, KEMPub](params.ChannelStateParams)
	return &Channel[Auth]{
		bgCtx:      params.Background,
		send:       params.Send,
		hsInterval: 1 * time.Second,

		state: &cs,
	}
}

func (c *Channel[Auth]) Send(ctx context.Context, msg p2p.IOVec) error {
	c.startHandshakeLoop()
	defer c.stopHandshakeLoop()
	select {}
	return nil
}

func (c *Channel[Auth]) Deliver(out []byte, inbound []byte) ([]byte, error) {
	now := tai64.Now()
	return c.state.Deliver(out, inbound, now)
}

func (c *Channel[Auth]) Remote() Auth {
	panic("")
}

func (c *Channel[Auth]) Close() error {
	return nil
}

func (c *Channel[Auth]) startHandshakeLoop() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.senderCount++
	if c.senderCount == 1 {
		ctx, cf := context.WithCancel(c.bgCtx)
		c.cf = cf
		go c.handshakeLoop(ctx)
	}
}

func (c *Channel[Auth]) stopHandshakeLoop() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.senderCount--
	if c.senderCount == 0 {
		c.cf()
	}
}

func (c *Channel[Auth]) handshakeLoop(ctx context.Context) {
	tick := time.NewTicker(c.hsInterval)
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
	}
}
