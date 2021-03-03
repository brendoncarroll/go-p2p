package swarmutil

import (
	"context"
	"io"
	"sync"
	"sync/atomic"

	"github.com/brendoncarroll/go-p2p"
	"github.com/pkg/errors"
)

const (
	stateWaiting = 0
	stateServing = 1
)

type hubCore struct {
	state uint32
	ready chan struct{}
	once  sync.Once
	done  chan struct{}
	err   error
}

func newHubCore() *hubCore {
	return &hubCore{
		ready: make(chan struct{}),
		done:  make(chan struct{}),
	}
}

func (h *hubCore) serve(setup func()) error {
	if !atomic.CompareAndSwapUint32(&h.state, stateWaiting, stateServing) {
		return errors.Errorf("already serving")
	}
	defer atomic.StoreUint32(&h.state, stateWaiting)
	setup()
	close(h.ready)
	<-h.done
	return h.err
}

func (h *hubCore) deliver(fn func()) {
	select {
	case <-h.done:
		return
	default:
		<-h.ready
		fn()
	}
}

func (h *hubCore) closeWithError(err error) {
	h.once.Do(func() {
		h.err = err
		close(h.done)
	})
}

type TellHub struct {
	*hubCore
	fn p2p.TellHandler
}

func NewTellHub() *TellHub {
	return &TellHub{hubCore: newHubCore()}
}

func (h *TellHub) ServeTells(fn p2p.TellHandler) error {
	return h.serve(func() {
		h.fn = fn
	})
}

func (h *TellHub) DeliverTell(msg *p2p.Message) {
	h.deliver(func() {
		h.fn(msg)
	})
}

func (h *TellHub) CloseWithError(err error) {
	h.closeWithError(err)
}

type AskHub struct {
	*hubCore
	fn p2p.AskHandler
}

func NewAskHub() *AskHub {
	return &AskHub{hubCore: newHubCore()}
}

func (h *AskHub) ServeAsks(fn p2p.AskHandler) error {
	return h.serve(func() {
		h.fn = fn
	})
}

func (h *AskHub) DeliverAsk(ctx context.Context, msg *p2p.Message, w io.Writer) {
	h.deliver(func() {
		h.fn(ctx, msg, w)
	})
}

func (h *AskHub) CloseWithError(err error) {
	h.closeWithError(err)
}
