package mbapp

import (
	"context"
	"sync"
)

type askID struct {
	GroupID
	Addr string
}

type ask struct {
	once    sync.Once
	done    chan struct{}
	respBuf []byte
	n       int
	errCode uint8
}

func (a *ask) await(ctx context.Context) error {
	select {
	case <-ctx.Done():
		a.abort()
		return ctx.Err()
	case <-a.done:
		return nil
	}
}

func (a *ask) complete(resp []byte, errCode uint8) {
	a.once.Do(func() {
		a.errCode = errCode
		a.n = copy(a.respBuf, resp)
		close(a.done)
	})
}

func (a *ask) abort() {
	a.once.Do(func() {
		close(a.done)
	})
}

type asker struct {
	mu       sync.RWMutex
	inFlight map[askID]*ask
}

func newAsker() *asker {
	return &asker{
		inFlight: make(map[askID]*ask),
	}
}

func (a *asker) createAsk(id askID, respBuf []byte) *ask {
	ask := &ask{
		done:    make(chan struct{}),
		respBuf: respBuf,
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	a.inFlight[id] = ask
	return ask
}

func (a *asker) removeAsk(id askID) {
	a.mu.Lock()
	defer a.mu.Unlock()
	delete(a.inFlight, id)
}

func (a *asker) getAndRemoveAsk(id askID) *ask {
	a.mu.Lock()
	defer a.mu.Unlock()
	ask := a.inFlight[id]
	delete(a.inFlight, id)
	return ask
}

func retry(ctx context.Context, fn func() error) error {
	return fn()
}
