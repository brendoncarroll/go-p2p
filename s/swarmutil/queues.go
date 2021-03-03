package swarmutil

import (
	"context"
	"io"
	"sync"

	"github.com/brendoncarroll/go-p2p"
)

type TellQueue struct {
	tells chan tell
	once  sync.Once
	err   error
}

func NewTellQueue() *TellQueue {
	return &TellQueue{
		tells: make(chan tell),
	}
}

func (q *TellQueue) ServeTell(ctx context.Context, fn p2p.TellHandler) error {
	tell, open := <-q.tells
	if !open {
		return q.err
	}
	defer close(tell.done)
	fn(tell.msg)
	return nil
}

func (q *TellQueue) DeliverTell(m *p2p.Message) {
	ch := make(chan struct{})
	q.tells <- tell{
		msg:  m,
		done: ch,
	}
	<-ch
}

func (q *TellQueue) CloseWithError(err error) {
	q.once.Do(func() {
		q.err = err
		close(q.tells)
	})
}

type tell struct {
	msg  *p2p.Message
	done chan struct{}
}

type AskQueue struct {
	asks chan ask
	once sync.Once
	err  error
}

func NewAskQueue() *AskQueue {
	return &AskQueue{
		asks: make(chan ask),
	}
}

func (q *AskQueue) ServeAsk(ctx context.Context, fn p2p.AskHandler) error {
	ask, open := <-q.asks
	if !open {
		return q.err
	}
	defer close(ask.done)
	fn(ask.ctx, ask.msg, ask.w)
	return nil
}

func (q *AskQueue) DeliverAsk(ctx context.Context, m *p2p.Message, w io.Writer) {
	ch := make(chan struct{})
	q.asks <- ask{
		ctx:  ctx,
		msg:  m,
		w:    w,
		done: ch,
	}
	<-ch
}

func (q *AskQueue) CloseWithError(err error) {
	q.once.Do(func() {
		q.err = err
		close(q.asks)
	})
}

type ask struct {
	ctx  context.Context
	msg  *p2p.Message
	w    io.Writer
	done chan struct{}
}
