package futures

import "context"

// NewSuccess returns a future which has already succeeded with x
func NewSuccess[T any](x T) Future[T] {
	return done[T]{x: x}
}

// NewFailure returns a future which has already failed with err
func NewFailure[T any](err error) Future[T] {
	return done[T]{err: err}
}

type done[T any] struct {
	x   T
	err error
}

func (f done[T]) wait(ctx context.Context) error {
	return nil
}

func (f done[T]) unwrap() (T, error) {
	return f.x, f.err
}

func (f done[T]) IsDone() bool {
	return true
}
