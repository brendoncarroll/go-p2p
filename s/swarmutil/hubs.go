package swarmutil

import (
	"context"
	"io"
	"sync"

	"github.com/brendoncarroll/go-p2p"
)

type TellHub struct {
	recvs chan *recvReq
	ready chan struct{}

	closeOnce sync.Once
	closed    chan struct{}
	err       error
}

func NewTellHub() *TellHub {
	return &TellHub{
		ready:  make(chan struct{}),
		recvs:  make(chan *recvReq),
		closed: make(chan struct{}),
	}
}

func (q *TellHub) Receive(ctx context.Context, src, dst *p2p.Addr, buf []byte) (int, error) {
	if err := q.checkClosed(); err != nil {
		return 0, err
	}
	req := &recvReq{
		buf:  buf,
		src:  src,
		dst:  dst,
		done: make(chan struct{}, 1),
	}
	select {
	case <-q.closed:
		return 0, q.err
	case q.recvs <- req:
		// non-blocking case
	default:
		// blocking case
		select {
		case <-ctx.Done():
			return 0, ctx.Err()
		case <-q.closed:
			return 0, q.err
		case q.recvs <- req:
		}
	}
	// once we get to here we are committed, unless the whole thing is closed we have to wait
	select {
	case <-q.closed:
		return 0, q.err
	case <-req.done:
		return req.n, req.err
	}
}

func (q *TellHub) Wait(ctx context.Context) error {
	if err := q.checkClosed(); err != nil {
		return err
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-q.closed:
		return q.err
	case <-q.ready:
		return nil
	}
}

// Deliver delivers a message to a caller of Recv
// If Deliver returns an error it will be from the context expiring.
func (q *TellHub) Deliver(ctx context.Context, m p2p.Message) error {
	return q.claim(ctx, func(src, dst *p2p.Addr, buf []byte) (int, error) {
		if len(buf) < len(m.Payload) {
			return 0, io.ErrShortBuffer
		}
		*src = m.Src
		*dst = m.Dst
		return copy(buf, m.Payload), nil
	})
}

// Claim calls fn, as if from a caller of Recv
// fn should never block
func (q *TellHub) claim(ctx context.Context, fn func(src, dst *p2p.Addr, buf []byte) (int, error)) error {
	// mark ready, until claim returns
	done := make(chan struct{})
	defer close(done)
	go func() {
		for {
			select {
			case q.ready <- struct{}{}:
			case <-done:
				return
			}
		}
	}()
	// wait for a request
	select {
	case <-q.closed:
		return q.err
	case <-ctx.Done():
		return ctx.Err()
	case req := <-q.recvs:
		// once we are here we are committed no using the context
		// req.done is buffered and should never block anyway
		req.n, req.err = fn(req.src, req.dst, req.buf)
		close(req.done)
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

type recvReq struct {
	src, dst *p2p.Addr
	buf      []byte

	done chan struct{}
	n    int
	err  error
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
	}
	// at this point we are committed
	select {
	case <-req.done:
		return nil
	case <-q.closed:
		return q.err
	}
}

func (q *AskHub) Deliver(ctx context.Context, respData []byte, req p2p.Message) (int, error) {
	select {
	case <-ctx.Done():
		return 0, ctx.Err()
	case serveReq := <-q.reqs:
		n, err := serveReq.fn(ctx, respData, req)
		close(serveReq.done)
		return n, err
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

type serveReq struct {
	fn   p2p.AskHandler
	done chan struct{}
}
