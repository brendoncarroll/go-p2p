package swarmutil

import (
	"context"
	"sync"

	"go.brendoncarroll.net/p2p"
)

type deliverReq[A p2p.Addr] struct {
	msg  p2p.Message[A]
	done chan struct{}
}

type TellHub[A p2p.Addr] struct {
	delivers chan *deliverReq[A]

	closeOnce sync.Once
	closed    chan struct{}
	err       error
}

func NewTellHub[A p2p.Addr]() TellHub[A] {
	return TellHub[A]{
		delivers: make(chan *deliverReq[A]),
		closed:   make(chan struct{}),
	}
}

func (q *TellHub[A]) Receive(ctx context.Context, fn func(p2p.Message[A])) error {
	if err := q.checkClosed(); err != nil {
		return err
	}
	select {
	case <-q.closed:
		return q.err
	case req := <-q.delivers:
		// non-blocking case
		defer close(req.done)
		fn(req.msg)
		return nil
	default:
		// blocking case
		select {
		case <-ctx.Done():
			return ctx.Err()
		case req, ok := <-q.delivers:
			if !ok {
				return q.err
			}
			defer close(req.done)
			fn(req.msg)
			return nil
		}
	}
}

// Deliver delivers a message to a caller of Recv
// If Deliver returns an error it will be from the context expiring.
func (q *TellHub[A]) Deliver(ctx context.Context, m p2p.Message[A]) error {
	req := &deliverReq[A]{
		msg:  m,
		done: make(chan struct{}),
	}
	select {
	case <-q.closed:
		return q.err
	case <-ctx.Done():
		return ctx.Err()
	case q.delivers <- req:
		// once we are here we are committed no using the context
		<-req.done
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
	if err == nil {
		err = p2p.ErrClosed
	}
	q.closeOnce.Do(func() {
		q.err = err
		close(q.closed)
	})
}

type serveReq[A p2p.Addr] struct {
	msg  p2p.Message[A]
	resp []byte
	n    int
	done chan struct{}
}

type AskHub[A p2p.Addr] struct {
	reqs chan *serveReq[A]

	closeOnce sync.Once
	closed    chan struct{}
	err       error
}

func NewAskHub[A p2p.Addr]() AskHub[A] {
	return AskHub[A]{
		reqs:   make(chan *serveReq[A]),
		closed: make(chan struct{}),
	}
}

func (q *AskHub[A]) ServeAsk(ctx context.Context, fn func(context.Context, []byte, p2p.Message[A]) int) error {
	if err := q.checkClosed(); err != nil {
		return err
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-q.closed:
		return q.err
	case req := <-q.reqs:
		req.n = fn(ctx, req.resp, req.msg)
		close(req.done)
		return nil
	}
}

func (q *AskHub[A]) Deliver(ctx context.Context, respData []byte, msg p2p.Message[A]) (int, error) {
	req := &serveReq[A]{
		msg:  msg,
		resp: respData,
		done: make(chan struct{}),
	}
	select {
	case <-ctx.Done():
		return 0, ctx.Err()
	case <-q.closed:
		return 0, q.err
	case q.reqs <- req:
		<-req.done
		return req.n, nil
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

func (q *AskHub[A]) Close() error {
	q.CloseWithError(nil)
	return nil
}

func (q *AskHub[A]) CloseWithError(err error) {
	q.closeOnce.Do(func() {
		q.err = err
		close(q.closed)
	})
}

func (q *AskHub[A]) String() string {
	return "AskHub{}"
}
