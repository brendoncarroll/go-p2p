package swarmutil

import (
	"context"
	"sync"

	"github.com/brendoncarroll/go-p2p"
)

type recvReq struct {
	fn   p2p.TellHandler
	done chan struct{}
}

type TellHub struct {
	recvs chan *recvReq

	closeOnce sync.Once
	closed    chan struct{}
	err       error
}

func NewTellHub() *TellHub {
	return &TellHub{
		recvs:  make(chan *recvReq),
		closed: make(chan struct{}),
	}
}

func (q *TellHub) Receive(ctx context.Context, fn p2p.TellHandler) error {
	if err := q.checkClosed(); err != nil {
		return err
	}
	req := &recvReq{
		fn:   fn,
		done: make(chan struct{}),
	}
	select {
	case <-q.closed:
		return q.err
	case q.recvs <- req:
		// non-blocking case
	default:
		// blocking case
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-q.closed:
			return q.err
		case q.recvs <- req:
		}
	}
	// once we get to here we are committed
	<-req.done
	return nil
}

// Deliver delivers a message to a caller of Recv
// If Deliver returns an error it will be from the context expiring.
func (q *TellHub) Deliver(ctx context.Context, m p2p.Message) error {
	// wait for a request
	select {
	case <-q.closed:
		return q.err
	case <-ctx.Done():
		return ctx.Err()
	case req := <-q.recvs:
		// once we are here we are committed no using the context
		defer close(req.done)
		req.fn(m)
		return nil
	}
}

func (q *TellHub) checkClosed() error {
	select {
	case <-q.closed:
		return q.err
	default:
		return nil
	}
}

func (q *TellHub) CloseWithError(err error) {
	q.closeOnce.Do(func() {
		q.err = err
		close(q.closed)
	})
}

type serveReq struct {
	fn   p2p.AskHandler
	done chan struct{}
}

type AskHub struct {
	reqs chan *serveReq

	closeOnce sync.Once
	closed    chan struct{}
	err       error
}

func NewAskHub() *AskHub {
	return &AskHub{
		reqs:   make(chan *serveReq),
		closed: make(chan struct{}),
	}
}

func (q *AskHub) ServeAsk(ctx context.Context, fn p2p.AskHandler) error {
	if err := q.checkClosed(); err != nil {
		return err
	}
	req := &serveReq{
		fn:   fn,
		done: make(chan struct{}, 1),
	}
	select {
	case <-q.closed:
		return q.err
	case <-ctx.Done():
		return ctx.Err()
	case q.reqs <- req:
		// at this point we are committed
		<-req.done
		return nil
	}
}

func (q *AskHub) Deliver(ctx context.Context, respData []byte, req p2p.Message) (int, error) {
	select {
	case <-q.closed:
		return 0, q.err
	case <-ctx.Done():
		return 0, ctx.Err()
	case serveReq := <-q.reqs:
		defer close(serveReq.done)
		n := serveReq.fn(ctx, respData, req)
		return n, nil
	}
}

func (q *AskHub) checkClosed() error {
	select {
	case <-q.closed:
		return q.err
	default:
		return nil
	}
}

func (q *AskHub) CloseWithError(err error) {
	q.closeOnce.Do(func() {
		q.err = err
		close(q.closed)
	})
}
