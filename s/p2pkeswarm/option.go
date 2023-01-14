package p2pkeswarm

import (
	"context"
	"time"

	"golang.org/x/crypto/sha3"

	"github.com/brendoncarroll/go-p2p"
	"github.com/brendoncarroll/go-p2p/f/x509"
)

type Fingerprinter = func(*x509.PublicKey) p2p.PeerID

type Option[T p2p.Addr] func(*swarmConfig[T])

type swarmConfig[T p2p.Addr] struct {
	bgCtx         context.Context
	fingerprinter Fingerprinter
	tellTimeout   time.Duration
	whitelist     func(Addr[T]) bool
	registry      x509.Registry
}

func newDefaultConfig[T p2p.Addr]() swarmConfig[T] {
	return swarmConfig[T]{
		bgCtx:         context.Background(),
		fingerprinter: DefaultFingerprinter,
		tellTimeout:   3 * time.Second,
		whitelist:     func(Addr[T]) bool { return true },
		registry:      x509.DefaultRegistry(),
	}
}

// DefaultFingerprinter returns a fingerprint for pub using SHAKE256
func DefaultFingerprinter(pub *x509.PublicKey) (ret p2p.PeerID) {
	out := x509.MarshalPublicKey(nil, pub)
	sha3.ShakeSum256(ret[:], out)
	return ret
}

// WithBackground sets the background context used by the swarm
func WithBackground[T p2p.Addr](ctx context.Context) Option[T] {
	return func(c *swarmConfig[T]) {
		c.bgCtx = ctx
	}
}

// WithFingerprinter sets the fingerprinter used by the swarm.
// The default is p2p.DefaultFingerprinter
func WithFingerprinter[T p2p.Addr](fp Fingerprinter) Option[T] {
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
