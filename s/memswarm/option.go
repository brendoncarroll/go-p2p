package memswarm

import (
	"context"
	"io"
)

type Option[Pub any] func(r *Realm[Pub])

func WithBackground[Pub any](ctx context.Context) Option[Pub] {
	return func(r *Realm[Pub]) {
		r.ctx = ctx
	}
}

func WithTrafficLogging[Pub any](w io.Writer) Option[Pub] {
	return func(r *Realm[Pub]) {
		r.trafficLog = w
	}
}

func WithTellTransform[Pub any](fn func(x *Message) bool) Option[Pub] {
	return func(r *Realm[Pub]) {
		r.tellTransform = fn
	}
}

func WithMTU[Pub any](x int) Option[Pub] {
	return func(r *Realm[Pub]) {
		r.mtu = x
	}
}

func WithBufferedTells[Pub any](n int) Option[Pub] {
	if n < 0 {
		panic("n < 0")
	}
	return func(r *Realm[Pub]) {
		r.bufferedTells = n
	}
}
