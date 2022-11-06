// package futures provides a Future type which can be used
// to model the result of a ongoing computation which could fail.
//
// Futures are not the idiomatic way to deal with concurrency in Go.
// Go APIs should be synchronous not asynchronous.
// If your API returns a Future: you are doing it wrong.
// That being said, The network *is* asynchronous, futures, especially the Promises, provide a way to build synchronous APIs
// on top of the asynchronous network.
package futures

import (
	"context"

	"golang.org/x/sync/errgroup"
)

type Future[T any] interface {
	// IsDone returns whether the future is done.  It does not block.
	IsDone() bool

	// wait blocks until the future is complete.
	// wait will only return errors from the context
	// wait will NOT return the result error
	wait(context.Context) error

	// unwrap returns the result of the future
	// it is unsafe to call this before wait has returned nil
	unwrap() (T, error)
}

func IsSuccess[T any](f Future[T]) bool {
	if !f.IsDone() {
		return false
	}
	_, err := f.unwrap()
	return err == nil
}

func IsFailure[T any](f Future[T]) bool {
	if !f.IsDone() {
		return false
	}
	_, err := f.unwrap()
	return err != nil
}

// Await blocks until the future is complete then returns the result.
func Await[T any](ctx context.Context, f Future[T]) (T, error) {
	if err := f.wait(ctx); err != nil {
		var zero T
		return zero, err
	}
	return f.unwrap()
}

func Await2[A, B any](ctx context.Context, af Future[A], bf Future[B]) (retA A, retB B, _ error) {
	ws := [2]waiter{af, bf}
	if err := waitAll(ctx, ws[:]); err != nil {
		return retA, retB, err
	}
	a, err := af.unwrap()
	if err != nil {
		return retA, retB, err
	}
	b, err := bf.unwrap()
	if err != nil {
		return retA, retB, err
	}
	return a, b, nil
}

func Await3[A, B, C any](ctx context.Context, af Future[A], bf Future[B], cf Future[C]) (retA A, retB B, retC C, _ error) {
	ws := [3]waiter{af, bf, cf}
	if err := waitAll(ctx, ws[:]); err != nil {
		return retA, retB, retC, err
	}
	a, err := af.unwrap()
	if err != nil {
		return retA, retB, retC, err
	}
	b, err := bf.unwrap()
	if err != nil {
		return retA, retB, retC, err
	}
	c, err := cf.unwrap()
	if err != nil {
		return retA, retB, retC, err
	}
	return a, b, c, nil
}

type waiter interface {
	wait(ctx context.Context) error
}

func waitAll(ctx context.Context, xs []waiter) error {
	eg, ctx := errgroup.WithContext(ctx)
	for i := range xs {
		i := i
		eg.Go(func() error { return xs[i].wait(ctx) })
	}
	return eg.Wait()
}
