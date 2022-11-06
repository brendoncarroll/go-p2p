package memswarm

import (
	"io"

	"golang.org/x/exp/slog"
)

type Option func(r *Realm)

func WithLogger(l slog.Logger) Option {
	return func(r *Realm) {
		r.log = l
	}
}

func WithTrafficLogging(w io.Writer) Option {
	return func(r *Realm) {
		r.trafficLog = w
	}
}

func WithTellTransform(fn func(x Message) *Message) Option {
	return func(r *Realm) {
		r.tellTransform = fn
	}
}

func WithMTU(x int) Option {
	return func(r *Realm) {
		r.mtu = x
	}
}

func WithBufferedTells(n int) Option {
	if n < 0 {
		panic("n < 0")
	}
	return func(r *Realm) {
		r.bufferedTells = n
	}
}
