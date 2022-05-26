package p2pkeswarm

import (
	"context"
	"runtime"
	"time"

	"github.com/brendoncarroll/go-p2p"
	"github.com/brendoncarroll/go-p2p/p/p2pke"
	"github.com/brendoncarroll/go-p2p/s/swarmutil"
	"github.com/sirupsen/logrus"
	"golang.org/x/sync/errgroup"
)

const Overhead = p2pke.Overhead

type Swarm[T p2p.Addr] struct {
	inner      p2p.Swarm[T]
	privateKey p2p.PrivateKey
	swarmConfig[T]
	whitelist func(Addr[T]) bool
	localID   p2p.PeerID

	hub   *swarmutil.TellHub[Addr[T]]
	store *store[string, *channelState]
	cf    context.CancelFunc
	eg    errgroup.Group
}

func New[T p2p.Addr](inner p2p.Swarm[T], privateKey p2p.PrivateKey, opts ...Option[T]) *Swarm[T] {
	config := swarmConfig[T]{
		log:           logrus.StandardLogger(),
		fingerprinter: p2p.DefaultFingerprinter,
		tellTimeout:   3 * time.Second,
		whitelist:     func(Addr[T]) bool { return true },
	}
	for _, opt := range opts {
		opt(&config)
	}
	ctx, cf := context.WithCancel(context.Background())
	s := &Swarm[T]{
		inner:       inner,
		privateKey:  privateKey,
		swarmConfig: config,

		hub:   swarmutil.NewTellHub[Addr[T]](),
		store: newStore[string, *channelState](),
		cf:    cf,
	}
	s.localID = s.fingerprinter(privateKey.Public())
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
func (s *Swarm[T]) PublicKey() p2p.PublicKey {
	return s.privateKey.Public()
}

// LookupPublicKey implements p2p.SecureSwarm.PublicKey
func (s *Swarm[T]) LookupPublicKey(ctx context.Context, dst Addr[T]) (p2p.PublicKey, error) {
	c, err := s.getFullAddr(ctx, dst)
	if err != nil {
		return nil, err
	}
	return c.RemoteKey(), nil
}

func (s *Swarm[T]) MTU(ctx context.Context, target Addr[T]) int {
	return s.inner.MTU(ctx, target.Addr.(T)) - Overhead
}

func (s *Swarm[T]) MaxIncomingSize() int {
	return s.inner.MaxIncomingSize() - Overhead
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
		c := s.store.getOrCreate(s.keyForAddr(addr.Addr.(T)), func() *channelState {
			return &channelState{
				CreatedAt: time.Now(),
				Channel: p2pke.NewChannel(p2pke.ChannelParams{
					PrivateKey: s.privateKey,
					AllowKey: func(pubKey p2p.PublicKey) bool {
						return s.fingerprinter(pubKey) == addr.ID
					},
					Send: s.getSender(addr.Addr.(T)),
				}),
			}
		})
		if err := c.Channel.WaitReady(ctx); err != nil {
			return nil, err
		}
		remoteID := s.fingerprinter(c.Channel.RemoteKey())
		if remoteID == addr.ID {
			return c.Channel, nil
		}
		s.store.deleteMatching(s.keyForAddr(addr.Addr.(T)), func(v *channelState) bool {
			return v.Channel == c.Channel
		})
	}
}

func (s *Swarm[T]) recvLoop(ctx context.Context) error {
	for {
		if err := s.inner.Receive(ctx, func(msg p2p.Message[T]) {
			if err := s.handleMessage(ctx, msg); err != nil {
				s.log.Warnf("p2pkeswarm: handling message from %v: %v", msg.Src, err)
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
			Channel: p2pke.NewChannel(p2pke.ChannelParams{
				PrivateKey: s.privateKey,
				AllowKey: func(pubKey p2p.PublicKey) bool {
					id := s.fingerprinter(pubKey)
					return s.whitelist(Addr[T]{ID: id, Addr: msg.Src})
				},
				Send: s.getSender(msg.Src),
			}),
		}
	})
	out, err := cs.Channel.Deliver(ctx, nil, msg.Payload)
	if err != nil {
		return err
	}
	if out != nil {
		srcID := s.fingerprinter(cs.Channel.RemoteKey())
		return s.hub.Deliver(ctx, p2p.Message[Addr[T]]{
			Src:     Addr[T]{ID: srcID, Addr: msg.Src},
			Dst:     Addr[T]{ID: s.localID, Addr: msg.Dst},
			Payload: out,
		})
	}
	return nil
}

func (s *Swarm[T]) getSender(dst T) p2pke.SendFunc {
	return func(x p2p.IOVec) {
		ctx, cf := context.WithTimeout(context.Background(), s.tellTimeout)
		defer cf()
		if err := s.inner.Tell(ctx, dst, x); err != nil {
			s.log.Debug("p2pkeswarm: during tell ", err)
		}
	}
}

func (s *Swarm[T]) cleanupLoop(ctx context.Context) error {
	const (
		gracePeriod   = 30 * time.Second
		timeoutPeriod = 30 * time.Second
	)
	ticker := time.NewTicker(p2pke.MaxSessionDuration / 2)
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
