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

type Option = func(s *Swarm)

func WithFingerprinter(fp p2p.Fingerprinter) Option {
	return func(s *Swarm) {
		s.fingerprinter = fp
	}
}

type Swarm struct {
	inner         p2p.Swarm
	privateKey    p2p.PrivateKey
	fingerprinter p2p.Fingerprinter
	log           *logrus.Logger
	localID       p2p.PeerID

	hub   *swarmutil.TellHub
	store *store
}

func New(inner p2p.Swarm, privateKey p2p.PrivateKey, opts ...Option) *Swarm {
	s := &Swarm{
		inner:         inner,
		privateKey:    privateKey,
		fingerprinter: p2p.DefaultFingerprinter,
		log:           logrus.StandardLogger(),

		hub:   swarmutil.NewTellHub(),
		store: newStore(privateKey),
	}
	for _, opt := range opts {
		opt(s)
	}
	s.localID = s.fingerprinter(privateKey.Public())
	go s.recvLoops(context.Background(), runtime.GOMAXPROCS(0))
	return s
}

func (s *Swarm) Tell(ctx context.Context, dst p2p.Addr, v p2p.IOVec) error {
	dst2 := dst.(Addr)
	return s.store.withConn(addrKey(dst2), func(c *p2pke.Conn) error {
		return c.Send(ctx, p2p.VecBytes(nil, v), s.getSender(ctx, dst))
	})
}

func (s *Swarm) Receive(ctx context.Context, th p2p.TellHandler) error {
	return s.hub.Receive(ctx, th)
}

func (s *Swarm) LocalAddrs() []p2p.Addr {
	addrs := s.inner.LocalAddrs()
	addrs2 := make([]p2p.Addr, 0, len(addrs))
	for _, addr := range addrs {
		addrs2 = append(addrs2, Addr{
			ID:   s.localID,
			Addr: addr,
		})
	}
	return addrs2
}

func (s *Swarm) PublicKey() p2p.PublicKey {
	return s.privateKey.Public()
}

func (s *Swarm) LookupPublicKey(ctx context.Context, dst p2p.Addr) (p2p.PublicKey, error) {
	dst2 := dst.(Addr)
	var ret p2p.PublicKey
	if err := s.store.withConn(addrKey(dst2), func(conn *p2pke.Conn) error {
		ret = conn.RemoteKey()
		return nil
	}); err != nil {
		return nil, err
	}
	return ret, nil
}

func (s *Swarm) MTU(ctx context.Context, target p2p.Addr) int {
	addr := target.(Addr)
	return s.inner.MTU(ctx, addr.Addr) - p2pke.Overhead
}

func (s *Swarm) MaxIncomingSize() int {
	return s.inner.MaxIncomingSize()
}

func (s *Swarm) Close() error {
	s.hub.CloseWithError(p2p.ErrClosed)
	return s.inner.Close()
}

func (s *Swarm) recvLoops(ctx context.Context, numWorkers int) error {
	eg := errgroup.Group{}
	for i := 0; i < numWorkers; i++ {
		eg.Go(func() error {
			for {
				if err := s.inner.Receive(ctx, func(msg p2p.Message) {
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

func (s *Swarm) handleMessage(ctx context.Context, msg p2p.Message) error {
	return s.store.withConn(addrKey(msg.Src), func(conn *p2pke.Conn) error {
		out, err := conn.Deliver(ctx, nil, msg.Payload, s.getSender(ctx, msg.Src))
		if err != nil {
			return err
		}
		if out != nil {
			return s.hub.Deliver(ctx, p2p.Message{
				Src:     Addr{ID: s.fingerprinter(conn.RemoteKey()), Addr: msg.Src},
				Dst:     Addr{ID: s.localID, Addr: msg.Dst},
				Payload: out,
			})
		}
		return nil
	})
}

func (s *Swarm) getSender(ctx context.Context, dst p2p.Addr) p2pke.Sender {
	return func(x []byte) {
		ctx, cf := context.WithTimeout(context.Background(), 1*time.Second)
		defer cf()
		if err := s.inner.Tell(ctx, dst, p2p.IOVec{x}); err != nil {
			s.log.Errorf("p2pkeswarm: during tell: %v", err)
		}
	}
}

func addrKey(x p2p.Addr) string {
	data, err := x.MarshalText()
	if err != nil {
		panic(err)
	}
	return string(data)
}
