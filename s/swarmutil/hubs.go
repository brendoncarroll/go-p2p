package swarmutil

import (
	"context"
	"sync"

	"github.com/brendoncarroll/go-p2p"
)

type recvReq[A p2p.Addr] struct {
	fn   p2p.TellHandler[A]
	done chan struct{}
}

type TellHub[A p2p.Addr] struct {
	recvs chan *recvReq[A]

	closeOnce sync.Once
	closed    chan struct{}
	err       error
}

func NewTellHub[A p2p.Addr]() *TellHub[A] {
	return &TellHub[A]{
		recvs:  make(chan *recvReq[A]),
		closed: make(chan struct{}),
	}
}

func (q *TellHub[A]) Receive(ctx context.Context, fn p2p.TellHandler[A]) error {
	if err := q.checkClosed(); err != nil {
		return err
	}
	req := &recvReq[A]{
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
func (q *TellHub[A]) Deliver(ctx context.Context, m p2p.Message[A]) error {
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

func (q *TellHub[A]) checkClosed() error {
	select {
	case <-q.closed:
		return q.err
	default:
		return nil
	}
}

func (q *TellHub[A]) CloseWithError(err error) {
	q.closeOnce.Do(func() {
		q.err = err
		close(q.closed)
	})
}

type serveReq[A p2p.Addr] struct {
	fn   p2p.AskHandler[A]
	done chan struct{}
}

type AskHub[A p2p.Addr] struct {
	reqs chan *serveReq[A]

	closeOnce sync.Once
	closed    chan struct{}
	err       error
}

func NewAskHub[A p2p.Addr]() *AskHub[A] {
	return &AskHub[A]{
		reqs:   make(chan *serveReq[A]),
		closed: make(chan struct{}),
	}
}

func (q *AskHub[A]) ServeAsk(ctx context.Context, fn p2p.AskHandler[A]) error {
	if err := q.checkClosed(); err != nil {
		return err
	}
	req := &serveReq[A]{
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

func (q *AskHub[A]) Deliver(ctx context.Context, respData []byte, req p2p.Message[A]) (int, error) {
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

func (q *AskHub[A]) checkClosed() error {
	select {
	case <-q.closed:
		return q.err
	default:
		return nil
	}
}

func (q *AskHub[A]) CloseWithError(err error) {
	q.closeOnce.Do(func() {
		q.err = err
		close(q.closed)
	})
}
