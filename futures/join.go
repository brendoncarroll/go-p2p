package futures

import (
	"context"
	"sync"
)

type pair[L, R any] struct {
	Left  L
	Right R
}

func newPair[L, R any](l L, r R) pair[L, R] {
	return pair[L, R]{Left: l, Right: r}
}

// Join2 takes 2 futures of different types and a merging function fn.
// Join2 returns a future containing the result of fn(a, b), where a is the value in afut, and b is the value in bfut
func Join2[A, B, Z any](afut Future[A], bfut Future[B], fn func(A, B) Z) Future[Z] {
	return &join2[A, B, Z]{
		a:  afut,
		b:  bfut,
		fn: fn,
	}
}

func Join3[A, B, C, Z any](a Future[A], b Future[B], c Future[C], fn func(A, B, C) Z) Future[Z] {
	return Join2(Join2(a, b, newPair[A, B]), c, func(p pair[A, B], c C) Z {
		return fn(p.Left, p.Right, c)
	})
}

func Join4[A, B, C, D, Z any](a Future[A], b Future[B], c Future[C], d Future[D], fn func(A, B, C, D) Z) Future[Z] {
	return Join2(Join2(a, b, newPair[A, B]), Join2(c, d, newPair[C, D]), func(l pair[A, B], r pair[C, D]) Z {
		return fn(l.Left, l.Right, r.Left, r.Right)
	})
}

type join2[A, B, Z any] struct {
	a Future[A]
	b Future[B]

	once sync.Once
	fn   func(A, B) Z
	out  Z
	err  error
}

func (f *join2[A, B, Z]) wait(ctx context.Context) error {
	ws := [2]waiter{f.a, f.b}
	return waitAll(ctx, ws[:])
}

func (f *join2[A, B, Z]) unwrap() (Z, error) {
	f.once.Do(func() {
		a, err := f.a.unwrap()
		if err != nil {
			f.err = err
			return
		}
		b, err := f.b.unwrap()
		if err != nil {
			f.err = err
			return
		}
		f.out = f.fn(a, b)
	})
	return f.out, f.err
}

func (f *join2[A, B, Z]) IsDone() bool {
	return f.a.IsDone() && f.b.IsDone()
}
