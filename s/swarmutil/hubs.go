package swarmutil

import (
	"context"
	"io"

	"github.com/brendoncarroll/go-p2p"
)

type TellHub struct {
	recvs  chan *recvReq
	closed chan struct{}
	err    error
}

func NewTellHub() *TellHub {
	return &TellHub{
		recvs:  make(chan *recvReq),
		closed: make(chan struct{}),
	}
}

func (q *TellHub) Recv(ctx context.Context, src, dst *p2p.Addr, buf []byte) (int, error) {
	if err := q.checkClosed(); err != nil {
		return 0, err
	}
	req := &recvReq{
		buf:  buf,
		src:  src,
		dst:  dst,
		done: make(chan struct{}, 1),
	}
	q.recvs <- req
	select {
	case <-q.closed:
		return 0, req.err
	case <-ctx.Done():
		return 0, ctx.Err()
	case <-req.done:
		return req.n, req.err
	}
}

func (q *TellHub) Deliver(ctx context.Context, m p2p.Message) error {
	select {
	case <-q.closed:
		return q.err
	case <-ctx.Done():
		return ctx.Err()
	case req := <-q.recvs:
		*req.src = m.Src
		*req.dst = m.Dst
		if len(req.buf) < len(m.Payload) {
			req.err = io.ErrShortBuffer
		} else {
			req.n = copy(req.buf, m.Payload)
		}
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
	q.err = err
	close(q.closed)
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

	closed chan struct{}
	err    error
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
	select {
	case <-ctx.Done():
		// TODO: fn could still be called if we return here
		return ctx.Err()
	case <-req.done:
		return nil
	}
}

func (q *AskHub) Deliver(ctx context.Context, respData []byte, req p2p.Message) (int, error) {
	select {
	case <-ctx.Done():
		return 0, ctx.Err()
	case serveReq := <-q.reqs:
		n := serveReq.fn(respData, req)
		close(serveReq.done)
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
	q.err = err
	close(q.closed)
}

type serveReq struct {
	fn   p2p.AskHandler
	done chan struct{}
}
