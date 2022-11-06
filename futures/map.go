package futures

import (
	"context"
	"sync"
)

type mapper[A, Z any] struct {
	x    Future[A]
	fn   func(A) Z
	once sync.Once
	y    Z
	err  error
}

func Map[A, Z any](x Future[A], fn func(A) Z) Future[Z] {
	return mapper[A, Z]{
		x:  x,
		fn: fn,
	}
}

func (m mapper[A, Z]) wait(ctx context.Context) error {
	return m.x.wait(ctx)
}

func (m mapper[A, Z]) unwrap() (Z, error) {
	m.once.Do(func() {
		x, err := m.x.unwrap()
		if err != nil {
			m.err = err
		} else {
			m.y = m.fn(x)
		}
	})
	return m.y, m.err
}

func (m mapper[A, Z]) IsDone() bool {
	return m.x.IsDone()
}
