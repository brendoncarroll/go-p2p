package simplemux

import (
	"context"

	"github.com/brendoncarroll/go-p2p"
)

type Swarm struct {
	m    *muxer
	name string

	handleAsk  p2p.AskHandler
	handleTell p2p.TellHandler
}

func newSwarm(m *muxer, name string) *Swarm {
	return &Swarm{
		m:    m,
		name: name,
	}
}

func (s *Swarm) OnTell(fn p2p.TellHandler) {
	s.handleTell = fn
}

func (s *Swarm) OnAsk(fn p2p.AskHandler) {
	if _, ok := s.m.s.(p2p.Asker); !ok {
		panic("underlying swarm does not support ask")
	}
	s.handleAsk = fn
}

func (s *Swarm) Tell(ctx context.Context, addr p2p.Addr, data []byte) error {
	i, err := s.m.lookup(ctx, addr, s.name)
	if err != nil {
		return err
	}
	msg := Message{}
	msg.SetChannel(i)
	msg.SetData(data)
	return s.m.s.Tell(ctx, addr, msg)
}

func (s *Swarm) Ask(ctx context.Context, addr p2p.Addr, data []byte) ([]byte, error) {
	return nil, nil
}

func (s *Swarm) MTU(ctx context.Context, addr p2p.Addr) int {
	return s.m.s.MTU(ctx, addr) - channelSize
}

func (s *Swarm) LocalAddrs() []p2p.Addr {
	return s.m.s.LocalAddrs()
}

func (s *Swarm) Close() error {
	return nil
}
