package natswarm

import (
	"context"
	"io"

	"github.com/brendoncarroll/go-p2p"
)

type Swarm struct {
	inner p2p.Swarm
	s     *service
}

func New(inner p2p.Swarm) p2p.Swarm {
	switch x := inner.(type) {
	case p2p.AskSwarm:
		return &AskSwarm{
			inner: x,
			s:     newService(inner),
		}
	default:
		return &Swarm{
			inner: x,
			s:     newService(inner),
		}
	}
}

func (s *Swarm) Tell(ctx context.Context, addr p2p.Addr, data []byte) error {
	return s.inner.Tell(ctx, addr, data)
}

func (s *Swarm) OnTell(fn p2p.TellHandler) {
	s.inner.OnTell(func(m *p2p.Message) {
		m.Dst = s.s.mapAddr(m.Dst)
		fn(m)
	})
}

func (s *Swarm) MTU(ctx context.Context, addr p2p.Addr) int {
	return s.inner.MTU(ctx, addr)
}

func (s *Swarm) LocalAddrs() []p2p.Addr {
	return s.s.mapAddrs(s.inner.LocalAddrs())
}

func (s *Swarm) Close() error {
	s.s.stop()
	return s.inner.Close()
}

type AskSwarm struct {
	inner p2p.AskSwarm
	s     *service
}

func (s *AskSwarm) Tell(ctx context.Context, addr p2p.Addr, data []byte) error {
	return s.inner.Tell(ctx, addr, data)
}

func (s *AskSwarm) OnTell(fn p2p.TellHandler) {
	s.inner.OnTell(func(m *p2p.Message) {
		m.Dst = s.s.mapAddr(m.Dst)
		fn(m)
	})
}

func (s *AskSwarm) Ask(ctx context.Context, addr p2p.Addr, data []byte) ([]byte, error) {
	return s.inner.Ask(ctx, addr, data)
}

func (s *AskSwarm) OnAsk(fn p2p.AskHandler) {
	s.inner.OnAsk(func(ctx context.Context, m *p2p.Message, w io.Writer) {
		m.Dst = s.s.mapAddr(m.Dst)
		fn(ctx, m, w)
	})
}

func (s *AskSwarm) MTU(ctx context.Context, addr p2p.Addr) int {
	return s.inner.MTU(ctx, addr)
}

func (s *AskSwarm) LocalAddrs() []p2p.Addr {
	return s.s.mapAddrs(s.inner.LocalAddrs())
}

func (s *AskSwarm) Close() error {
	return s.inner.Close()
}
