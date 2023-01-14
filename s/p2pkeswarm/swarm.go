package p2pkeswarm

import (
	"context"
	"runtime"
	"time"

	"github.com/brendoncarroll/stdctx/logctx"
	"golang.org/x/exp/constraints"
	"golang.org/x/sync/errgroup"

	"github.com/brendoncarroll/go-p2p"
	"github.com/brendoncarroll/go-p2p/f/x509"
	"github.com/brendoncarroll/go-p2p/p/p2pke"
	"github.com/brendoncarroll/go-p2p/s/swarmutil"
	"github.com/brendoncarroll/go-p2p/s/udpswarm"
)

const Overhead = p2pke.Overhead

var _ p2p.SecureSwarm[Addr[udpswarm.Addr], x509.PublicKey] = &Swarm[udpswarm.Addr]{}

type Swarm[T p2p.Addr] struct {
	inner      p2p.Swarm[T]
	privateKey x509.PrivateKey
	publicKey  x509.PublicKey
	config     swarmConfig[T]

	localID p2p.PeerID
	hub     *swarmutil.TellHub[Addr[T]]
	store   *store[string, *channelState]
	ctx     context.Context
	cf      context.CancelFunc
	eg      errgroup.Group
}

func New[T p2p.Addr](inner p2p.Swarm[T], privateKey x509.PrivateKey, opts ...Option[T]) *Swarm[T] {
	config := newDefaultConfig[T]()
	for _, opt := range opts {
		opt(&config)
	}
	pubKey, err := config.registry.PublicFromPrivate(&privateKey)
	if err != nil {
		panic(err)
	}
	ctx := config.bgCtx
	ctx, cf := context.WithCancel(ctx)
	s := &Swarm[T]{
		inner:      inner,
		privateKey: privateKey,
		publicKey:  pubKey,
		config:     config,
		localID:    config.fingerprinter(&pubKey),

		hub:   swarmutil.NewTellHub[Addr[T]](),
		store: newStore[string, *channelState](),
		ctx:   ctx,
		cf:    cf,
	}
	numWorkers := 1 + runtime.GOMAXPROCS(0)
	for i := 0; i < numWorkers; i++ {
		s.eg.Go(func() error {
			return s.recvLoop(ctx)
		})
	}
	s.eg.Go(func() error {
		return s.cleanupLoop(ctx)
	})
	return s
}

// Tell implements p2p.Swarm.Tell
func (s *Swarm[T]) Tell(ctx context.Context, dst Addr[T], v p2p.IOVec) error {
	if p2p.VecSize(v) > s.MTU(ctx, dst) {
		return p2p.ErrMTUExceeded
	}
	c, err := s.getFullAddr(ctx, dst)
	if err != nil {
		return err
	}
	return c.Send(ctx, v)
}

// Receive implements p2p.Swarm.Receive
func (s *Swarm[T]) Receive(ctx context.Context, th func(p2p.Message[Addr[T]])) error {
	return s.hub.Receive(ctx, th)
}

// LocalAddrs implements p2p.Swarm.LocalAddrs
func (s *Swarm[T]) LocalAddrs() []Addr[T] {
	addrs := s.inner.LocalAddrs()
	addrs2 := make([]Addr[T], 0, len(addrs))
	for _, addr := range addrs {
		addrs2 = append(addrs2, Addr[T]{
			ID:   s.localID,
			Addr: addr,
		})
	}
	return addrs2
}

// PublicKey implements p2p.SecureSwarm.PublicKey
func (s *Swarm[T]) PublicKey() x509.PublicKey {
	return s.publicKey
}

// LookupPublicKey implements p2p.SecureSwarm.PublicKey
func (s *Swarm[T]) LookupPublicKey(ctx context.Context, dst Addr[T]) (ret x509.PublicKey, _ error) {
	c, err := s.getFullAddr(ctx, dst)
	if err != nil {
		return ret, err
	}
	return c.RemoteKey(), nil
}

func (s *Swarm[T]) MTU(ctx context.Context, target Addr[T]) int {
	n := s.inner.MTU(ctx, target.Addr) - Overhead
	return min(n, p2pke.MaxMessageLen)
}

func (s *Swarm[T]) MaxIncomingSize() int {
	n := s.inner.MaxIncomingSize() - Overhead
	return min(n, p2pke.MaxMessageLen)
}

func (s *Swarm[T]) Close() error {
	s.cf()
	err := s.inner.Close()
	s.hub.CloseWithError(p2p.ErrClosed)
	s.eg.Wait()
	return err
}

// getFullAddr returns a p2pke.Channel which matches the full Addr addr.
func (s *Swarm[T]) getFullAddr(ctx context.Context, addr Addr[T]) (*p2pke.Channel, error) {
	for {
		c := s.store.getOrCreate(s.keyForAddr(addr.Addr), func() *channelState {
			return &channelState{
				CreatedAt: time.Now(),
				Channel: p2pke.NewChannel(p2pke.ChannelConfig{
					PrivateKey: s.privateKey,
					AcceptKey: func(pubKey *x509.PublicKey) bool {
						id := s.config.fingerprinter(pubKey)
						return id == addr.ID
					},
					Send: s.getSender(addr.Addr),
				}),
			}
		})
		if err := c.Channel.WaitReady(ctx); err != nil {
			return nil, err
		}
		remoteKey := c.Channel.RemoteKey()
		remoteID := s.config.fingerprinter(&remoteKey)
		if remoteID == addr.ID {
			return c.Channel, nil
		}
		s.store.deleteMatching(s.keyForAddr(addr.Addr), func(v *channelState) bool {
			return v.Channel == c.Channel
		})
	}
}

func (s *Swarm[T]) recvLoop(ctx context.Context) error {
	for {
		if err := s.inner.Receive(ctx, func(msg p2p.Message[T]) {
			if err := s.handleMessage(ctx, msg); err != nil {
				logctx.Warnf(ctx, "p2pkeswarm: handling message from %v: %v", msg.Src, err)
			}
		}); err != nil {
			return err
		}
	}
}

func (s *Swarm[T]) handleMessage(ctx context.Context, msg p2p.Message[T]) error {
	cs := s.store.getOrCreate(s.keyForAddr(msg.Src), func() *channelState {
		return &channelState{
			CreatedAt: time.Now(),
			Channel: p2pke.NewChannel(p2pke.ChannelConfig{
				PrivateKey: s.privateKey,
				AcceptKey: func(pubKey *x509.PublicKey) bool {
					id := s.config.fingerprinter(pubKey)
					return s.config.whitelist(Addr[T]{ID: id, Addr: msg.Src})
				},
				Send: s.getSender(msg.Src),
			}),
		}
	})
	out, err := cs.Channel.Deliver(nil, msg.Payload)
	if err != nil {
		return err
	}
	if out != nil {
		remoteKey := cs.Channel.RemoteKey()
		srcID := s.config.fingerprinter(&remoteKey)
		return s.hub.Deliver(ctx, p2p.Message[Addr[T]]{
			Src:     Addr[T]{ID: srcID, Addr: msg.Src},
			Dst:     Addr[T]{ID: s.localID, Addr: msg.Dst},
			Payload: out,
		})
	}
	return nil
}

func (s *Swarm[T]) getSender(dst T) p2pke.SendFunc {
	return func(x []byte) {
		ctx, cf := context.WithTimeout(s.ctx, s.config.tellTimeout)
		defer cf()
		if err := s.inner.Tell(ctx, dst, p2p.IOVec{x}); err != nil {
			logctx.Debugln(ctx, "p2pkeswarm: during tell ", err)
		}
	}
}

func (s *Swarm[T]) cleanupLoop(ctx context.Context) error {
	const (
		gracePeriod   = 30 * time.Second
		timeoutPeriod = p2pke.KeepAliveTimeout
	)
	ticker := time.NewTicker(p2pke.KeepAliveTimeout / 2)
	defer ticker.Stop()
	now := time.Now()
	for {
		s.store.purge(func(addr string, c *channelState) bool {
			if now.Sub(c.CreatedAt) < gracePeriod {
				return true
			}
			if now.Sub(c.Channel.LastReceived()) < timeoutPeriod {
				return true
			}
			if now.Sub(c.Channel.LastSent()) < timeoutPeriod {
				return true
			}
			c.Channel.Close()
			return false
		})
		select {
		case <-ctx.Done():
			return ctx.Err()
		case now = <-ticker.C:
		}
	}
}

func (s *Swarm[T]) keyForAddr(x T) string {
	data, err := x.MarshalText()
	if err != nil {
		panic(err)
	}
	return string(data)
}

type channelState struct {
	Channel   *p2pke.Channel
	CreatedAt time.Time
}

func min[T constraints.Ordered](xs ...T) (ret T) {
	if len(xs) > 0 {
		ret = xs[0]
	}
	for i := range xs {
		if xs[i] < ret {
			ret = xs[i]
		}
	}
	return ret
}
