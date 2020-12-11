package memswarm

import (
	"io"
	"time"

	"github.com/jonboulle/clockwork"
)

type Option func(r *Realm)

func WithLogging(w io.Writer) Option {
	return func(r *Realm) {
		r.logw = w
	}
}

func WithLatency(t time.Duration) Option {
	return func(r *Realm) {
		if r.clock == nil {
			r.clock = clockwork.NewFakeClock()
		}
		r.latency = t
	}
}

func WithClock(clock clockwork.Clock) Option {
	return func(r *Realm) {
		r.clock = clock
	}
}

func WithDropRate(dr float64) Option {
	return func(r *Realm) {
		r.dropRate = dr
	}
}

func WithMTU(x int) Option {
	return func(r *Realm) {
		r.mtu = x
	}
}
