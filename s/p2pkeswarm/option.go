package p2pkeswarm

import (
	"io"
	"time"

	"github.com/brendoncarroll/go-p2p"
	"golang.org/x/exp/slog"
)

type Option[T p2p.Addr] func(*swarmConfig[T])

type swarmConfig[T p2p.Addr] struct {
	log           slog.Logger
	fingerprinter p2p.Fingerprinter
	tellTimeout   time.Duration
	whitelist     func(Addr[T]) bool
}

func newDefaultConfig[T p2p.Addr]() swarmConfig[T] {
	return swarmConfig[T]{
		log:           slog.New(slog.NewTextHandler(io.Discard)),
		fingerprinter: p2p.DefaultFingerprinter,
		tellTimeout:   3 * time.Second,
		whitelist:     func(Addr[T]) bool { return true },
	}
}

// WithLogger sets the logger used by the swarm
func WithLogger[T p2p.Addr](log slog.Logger) Option[T] {
	return func(c *swarmConfig[T]) {
		c.log = log
	}
}

// WithFingerprinter sets the fingerprinter used by the swarm.
// The default is p2p.DefaultFingerprinter
func WithFingerprinter[T p2p.Addr](fp p2p.Fingerprinter) Option[T] {
	return func(c *swarmConfig[T]) {
		c.fingerprinter = fp
	}
}

// WithWhitelist sets the whitelist for incoming messages.
// If !fn(msg.Src) then the message is dropped.
func WithWhitelist[T p2p.Addr](fn func(Addr[T]) bool) Option[T] {
	return func(c *swarmConfig[T]) {
		c.whitelist = fn
	}
}
