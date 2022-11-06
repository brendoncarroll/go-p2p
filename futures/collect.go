package futures

import (
	"context"
	"sync"
)

type collectSlice[T any] struct {
	xs   []Future[T]
	once sync.Once
	y    []T
	err  error
}

// CollectSlice converts a slice of Futures of type T to a single future of a slice of type T.
func CollectSlice[T any](futs []Future[T]) Future[[]T] {
	return &collectSlice[T]{xs: futs}
}

func (f *collectSlice[T]) IsDone() bool {
	for _, x := range f.xs {
		if !x.IsDone() {
			return false
		}
	}
	return true
}

func (f *collectSlice[T]) wait(ctx context.Context) error {
	ws := make([]waiter, len(f.xs))
	for i := range ws {
		ws[i] = f.xs[i]
	}
	return waitAll(ctx, ws)
}

func (f *collectSlice[T]) unwrap() ([]T, error) {
	f.once.Do(func() {
		y := make([]T, len(f.xs))
		for i := range f.xs {
			x, err := f.xs[i].unwrap()
			if err != nil {
				f.err = err
				return
			}
			f.y[i] = x
		}
		f.y = y
	})
	return f.y, f.err
}
