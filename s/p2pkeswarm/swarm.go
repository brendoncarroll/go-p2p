package p2pkeswarm

import (
	"context"

	"github.com/brendoncarroll/go-p2p"
	p2pke "github.com/brendoncarroll/go-p2p/p/p2pke2"
	"github.com/brendoncarroll/go-tai64"
	"github.com/brendoncarroll/stdctx/logctx"
)

type Swarm[A p2p.Addr, Pub any] struct {
	inner p2p.Swarm[K]
	host  p2pke.Host[sessionKey]

	cf context.CancelFunc
	eg errgroup.Group
}

func NewSwarm[A p2p.Addr, Pub any](inner p2p.Swarm[A]) *Swarm[A, Pub] {
	ctx := context.Background()
	ctx, cf := context.WithCancel(ctx)
	s := &Swarm[A, Pub]{
		inner: inner,
		host:  p2pke.NewHost(),

		cf: cf,
	}
	s.eg.Go(func() error {
		return nil
	})
	return s
}

func (s *Swarm[A, Pub]) Send(ctx context.Context, dst A, v p2p.IOVec) error {
	now := tai64.Now()
	return s.host.Send(ctx, newKey(dst), now, p2p.VecBytes(v), func(data []byte) {
		return s.inner.Send(ctx, data)
	})
}

func (s *Swarm[A, Pub]) Receive(ctx context.Context, fn func(p2p.Message[A])) error {
	for gotOne := false; !gotOne; {
		if err := s.inner.Receive(ctx, func(msg p2p.Message[A]) {
			now := tai64.Now()
			// TODO: can reuse message buffer
			out, err := s.host.Deliver(nil, msg.Payload, now)
			if err != nil {
				logctx.Errorln(ctx, err)
				return
			}
			fn(p2p.Message[A]{
				Src:     msg.Src,
				Dst:     msg.Dst,
				Payload: out,
			})
			gotOne = true
		}); err != nil {
			return err
		}
	}
	return nil
}

func (s *Swarm[A, Pub]) LocalAddrs() []A {
	return []A{}
}

func (s *Swarm[A, Pub]) PublicKey() (ret Pub) {
	return ret
}

func (s *Swarm[A, Pub]) LookupPublicKey(ctx context.Context) (ret Pub, _ error) {
	return ret, nil
}

func (s *Swarm[A, Pub]) Close() error {
	s.cf()
	return s.eg.Wait()
}

type sessionKey string

func newKey(a p2p.Addr) sessionKey {
	data, _ := a.MarshalText()
	return string(data)
}
