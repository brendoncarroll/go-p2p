package swarmutil

import (
	"context"
	"io"
	"sync"

	"github.com/brendoncarroll/go-p2p"
)

type THCell struct {
	mu     sync.RWMutex
	onTell p2p.TellHandler
}

func (c *THCell) Handle(msg *p2p.Message) {
	c.mu.RLock()
	onTell := c.onTell
	c.mu.RUnlock()
	if onTell == nil {
		onTell = p2p.NoOpTellHandler
	}
	onTell(msg)
}

func (c *THCell) Set(fn p2p.TellHandler) {
	if fn == nil {
		fn = p2p.NoOpTellHandler
	}
	c.mu.Lock()
	c.onTell = fn
	c.mu.Unlock()
}

type AHCell struct {
	mu    sync.RWMutex
	onAsk p2p.AskHandler
}

func (c *AHCell) Handle(ctx context.Context, msg *p2p.Message, w io.Writer) {
	c.mu.RLock()
	onAsk := c.onAsk
	c.mu.RUnlock()
	if onAsk == nil {
		onAsk = p2p.NoOpAskHandler
	}
	onAsk(ctx, msg, w)
}

func (c *AHCell) Set(fn p2p.AskHandler) {
	if fn == nil {
		fn = p2p.NoOpAskHandler
	}
	c.mu.Lock()
	c.onAsk = fn
	c.mu.Unlock()
}
