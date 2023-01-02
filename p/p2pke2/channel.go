package p2pke2

import (
	"context"
	"sync"
	"time"

	"github.com/brendoncarroll/go-p2p"
	"github.com/brendoncarroll/go-tai64"
)

type SendFunc = func([]byte)

type ChannelParams[S any] struct {
	Background context.Context
	Send       SendFunc
	ChannelStateParams[S]
}

type Channel[S any] struct {
	bgCtx      context.Context
	send       SendFunc
	hsInterval time.Duration

	mu          sync.Mutex
	state       ChannelState[S]
	senderCount int
	cf          context.CancelFunc
	ready       chan struct{}
}

func NewChannel[S any](params ChannelParams[S]) *Channel[S] {
	return &Channel[S]{
		bgCtx:      params.Background,
		send:       params.Send,
		hsInterval: 1 * time.Second,

		state: NewChannelState(params.ChannelStateParams),
	}
}

func (c *Channel[S]) Send(ctx context.Context, msg p2p.IOVec) error {
	c.startHandshakeLoop()
	defer c.stopHandshakeLoop()
	select {}
	return nil
}

func (c *Channel[S]) Deliver(out []byte, inbound []byte) ([]byte, error) {
	now := tai64.Now()
	return c.state.Deliver(out, inbound, now)
}

func (c *Channel[S]) Close() error {
	return nil
}

func (c *Channel[S]) startHandshakeLoop() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.senderCount++
	if c.senderCount == 1 {
		ctx, cf := context.WithCancel(c.bgCtx)
		c.cf = cf
		go c.handshakeLoop(ctx)
	}
}

func (c *Channel[S]) stopHandshakeLoop() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.senderCount--
	if c.senderCount == 0 {
		c.cf()
	}
}

func (c *Channel[S]) handshakeLoop(ctx context.Context) {
	tick := time.NewTicker(c.hsInterval)
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
	}
}
