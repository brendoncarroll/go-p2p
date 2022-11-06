package futures

import (
	"context"
	"sync"
)

// Go spawns fn in a separate Goroutine and returns a Future for it's completion
func Go[T any](fn func() (T, error)) Future[T] {
	p := NewPromise[T]()
	go func() {
		x, err := fn()
		if err != nil {
			p.Fail(err)
		} else {
			p.Succeed(x)
		}
	}()
	return p
}

type Promise[T any] struct {
	once  sync.Once
	done  chan struct{}
	value T
	err   error
}

func NewPromise[T any]() *Promise[T] {
	return &Promise[T]{done: make(chan struct{})}
}

func (f *Promise[T]) IsDone() bool {
	select {
	case <-f.done:
		return true
	default:
		return false
	}
}

func (f *Promise[T]) IsFailure() bool {
	return f.IsDone() && f.err != nil
}

func (f *Promise[T]) IsSuccess() bool {
	return f.IsDone() && f.err == nil
}

func (f *Promise[T]) Succeed(x T) (ret bool) {
	f.once.Do(func() {
		ret = true
		f.value = x
		close(f.done)
	})
	return ret
}

func (f *Promise[T]) Fail(err error) (ret bool) {
	f.once.Do(func() {
		ret = true
		f.err = err
		close(f.done)
	})
	return ret
}

func (f *Promise[T]) wait(ctx context.Context) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-f.done:
		return nil
	}
}

func (f *Promise[T]) unwrap() (T, error) {
	if !f.IsDone() {
		panic("unwrap called on incomplete promise")
	}
	return f.value, f.err
}
