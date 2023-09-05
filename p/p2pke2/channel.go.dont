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
	Now        func() tai64.TAI64N

	ChannelStateParams[S]
}

type Channel[S any] struct {
	bgCtx      context.Context
	send       SendFunc
	now        func() tai64.TAI64N
	hsInterval time.Duration

	mu          sync.Mutex
	state       ChannelState[S]
	senderCount int
	cf          context.CancelFunc
	ready       chan struct{}
}

func NewChannel[S any](params ChannelParams[S]) *Channel[S] {
	if params.Send == nil {
		panic(params.Send)
	}
	return &Channel[S]{
		bgCtx:      params.Background,
		send:       params.Send,
		now:        params.Now,
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
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.state.Deliver(out, c.now(), inbound)
}

func (c *Channel[S]) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.cf()
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
	var buf []byte
	tick := time.NewTicker(c.hsInterval)
	for {
		now := c.now()
		c.mu.Lock()
		isReady := c.state.IsReady(now)
		if !isReady {
			var err error
			buf, err = c.state.SendHandshake(buf[:0], now)
			c.mu.Unlock()
			if err == nil {
				c.send(buf)
			}
		} else {
			c.mu.Unlock()
		}
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
	}
}
