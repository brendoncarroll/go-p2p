package p2pkeswarm

import (
	"context"
	"runtime"
	"time"

	"github.com/brendoncarroll/go-p2p"
	"github.com/brendoncarroll/go-p2p/p/p2pke"
	"github.com/brendoncarroll/go-p2p/s/swarmutil"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"golang.org/x/sync/errgroup"
)

type swarmConfig struct {
	fingerprinter p2p.Fingerprinter
}

type Option func(s *swarmConfig)

func WithFingerprinter(fp p2p.Fingerprinter) Option {
	return func(c *swarmConfig) {
		c.fingerprinter = fp
	}
}

type Swarm[T p2p.Addr] struct {
	inner         p2p.Swarm[T]
	privateKey    p2p.PrivateKey
	fingerprinter p2p.Fingerprinter
	log           *logrus.Logger
	localID       p2p.PeerID

	hub   *swarmutil.TellHub[Addr[T]]
	store *store[T]
}

func New[T p2p.Addr](inner p2p.Swarm[T], privateKey p2p.PrivateKey, opts ...Option) *Swarm[T] {	
	config := swarmConfig{
		fingerprinter: p2p.DefaultFingerprinter,
	}
	for _, opt := range opts {
		opt(&config)
	}
	s := &Swarm[T]{
		inner:         inner,
		privateKey:    privateKey,
		log:           logrus.StandardLogger(),
		hub:           swarmutil.NewTellHub[Addr[T]](),
		fingerprinter: config.fingerprinter,
	}
	s.localID = s.fingerprinter(privateKey.Public())
	s.store = newStore(func(addr Addr[T]) *p2pke.Channel {
		checkKey := func(p2p.PublicKey) error { return nil }
		if addr.ID != (p2p.PeerID{}) {
			checkKey = func(x p2p.PublicKey) error {
				return checkPublicKey(s.fingerprinter, addr.ID, x)
			}
		}
		return p2pke.NewChannel(s.privateKey, checkKey)
	})
	go s.recvLoops(context.Background(), runtime.GOMAXPROCS(0))
	return s
}

func (s *Swarm[T]) Tell(ctx context.Context, dst Addr[T], v p2p.IOVec) error {
	if p2p.VecSize(v) > s.MTU(ctx, dst) {
		return p2p.ErrMTUExceeded
	}
	return s.withConn(ctx, dst, func(c *p2pke.Channel) error {
		return c.Send(ctx, p2p.VecBytes(nil, v), s.getSender(ctx, dst.Addr))
	})
}

func (s *Swarm[T]) Receive(ctx context.Context, th p2p.TellHandler[Addr[T]]) error {
	return s.hub.Receive(ctx, th)
}

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

func (s *Swarm[T]) PublicKey() p2p.PublicKey {
	return s.privateKey.Public()
}

func (s *Swarm[T]) LookupPublicKey(ctx context.Context, dst Addr[T]) (p2p.PublicKey, error) {
	var ret p2p.PublicKey
	if err := s.withConn(ctx, dst, func(conn *p2pke.Channel) error {
		ret = conn.RemoteKey()
		return nil
	}); err != nil {
		return nil, err
	}
	if ret == nil {
		return nil, p2p.ErrPublicKeyNotFound
	}
	return ret, nil
}

func (s *Swarm[T]) MTU(ctx context.Context, target Addr[T]) int {
	return s.inner.MTU(ctx, target.Addr) - p2pke.Overhead
}

func (s *Swarm[T]) MaxIncomingSize() int {
	return s.inner.MaxIncomingSize()
}

func (s *Swarm[T]) Close() error {
	s.hub.CloseWithError(p2p.ErrClosed)
	return s.inner.Close()
}

func (s *Swarm[T]) withConn(ctx context.Context, addr Addr[T], fn func(*p2pke.Channel) error) error {
	shouldDelete := false
	defer func() {
		if shouldDelete {
			s.store.delete(addr)
		}
	}()
	return s.store.withConn(addr, func(c *p2pke.Channel) error {
		if err := c.WaitReady(ctx, s.getSender(ctx, addr.Addr)); err != nil {
			return err
		}
		if err := checkPublicKey(s.fingerprinter, addr.ID, c.RemoteKey()); err != nil {
			shouldDelete = true
			return err
		}
		return fn(c)
	})
}

func (s *Swarm[T]) recvLoops(ctx context.Context, numWorkers int) error {
	eg := errgroup.Group{}
	for i := 0; i < numWorkers; i++ {
		eg.Go(func() error {
			for {
				if err := s.inner.Receive(ctx, func(msg p2p.Message[T]) {
					if err := s.handleMessage(ctx, msg); err != nil {
						s.log.Warnf("handling message from %v: %v", msg.Src, err)
					}
				}); err != nil {
					return err
				}
			}
		})
	}
	return eg.Wait()
}

func (s *Swarm[T]) handleMessage(ctx context.Context, msg p2p.Message[T]) error {
	return s.store.withConn(Addr[T]{ID: p2p.PeerID{}, Addr: msg.Src}, func(conn *p2pke.Channel) error {
		out, err := conn.Deliver(ctx, nil, msg.Payload, s.getSender(ctx, msg.Src))
		if err != nil {
			return err
		}
		if out != nil {
			srcID := s.fingerprinter(conn.RemoteKey())
			return s.hub.Deliver(ctx, p2p.Message[Addr[T]]{
				Src:     Addr[T]{ID: srcID, Addr: msg.Src},
				Dst:     Addr[T]{ID: s.localID, Addr: msg.Dst},
				Payload: out,
			})
		}
		return nil
	})
}

func (s *Swarm[T]) getSender(ctx context.Context, dst T) p2pke.Sender {
	return func(x []byte) {
		ctx, cf := context.WithTimeout(context.Background(), 1*time.Second)
		defer cf()
		if err := s.inner.Tell(ctx, dst, p2p.IOVec{x}); err != nil {
			s.log.Errorf("p2pkeswarm: during tell: %v", err)
		}
	}
}

func checkPublicKey(fp p2p.Fingerprinter, id p2p.PeerID, x p2p.PublicKey) error {
	have := fp(x)
	want := id
	if have != want {
		return errors.Errorf("wrong peer id HAVE: %v WANT: %v", have, want)
	}
	return nil
}
