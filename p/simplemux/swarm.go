package simplemux

import (
	"context"

	"github.com/brendoncarroll/go-p2p"
)

type baseSwarm struct {
	m    *muxer
	name string

	handleAsk  p2p.AskHandler
	handleTell p2p.TellHandler
}

func newSwarm(m *muxer, name string) *baseSwarm {
	return &baseSwarm{
		m:    m,
		name: name,
	}
}

func (s *baseSwarm) OnTell(fn p2p.TellHandler) {
	s.handleTell = fn
}

func (s *baseSwarm) OnAsk(fn p2p.AskHandler) {
	if _, ok := s.m.s.(p2p.Asker); !ok {
		panic("underlying swarm does not support ask")
	}
	s.handleAsk = fn
}

func (s *baseSwarm) Tell(ctx context.Context, addr p2p.Addr, data []byte) error {
	i, err := s.m.lookup(ctx, addr, s.name)
	if err != nil {
		return err
	}
	msg := Message{}
	msg.SetChannel(i)
	msg.SetData(data)
	return s.m.s.Tell(ctx, addr, msg)
}

func (s *baseSwarm) Ask(ctx context.Context, addr p2p.Addr, data []byte) ([]byte, error) {
	innerSwarm := s.m.s.(p2p.AskSwarm)
	i, err := s.m.lookup(ctx, addr, s.name)
	if err != nil {
		return nil, err
	}
	msg := Message{}
	msg.SetChannel(i)
	msg.SetData(data)
	return innerSwarm.Ask(ctx, addr, msg)
}

func (s *baseSwarm) MTU(ctx context.Context, addr p2p.Addr) int {
	return s.m.s.MTU(ctx, addr) - channelSize
}

func (s *baseSwarm) LocalAddrs() []p2p.Addr {
	return s.m.s.LocalAddrs()
}

func (s *baseSwarm) Close() error {
	s.handleAsk = p2p.NoOpAskHandler
	s.handleTell = p2p.NoOpTellHandler
	return nil
}

func (s *baseSwarm) ParseAddr(data []byte) (p2p.Addr, error) {
	return s.m.s.ParseAddr(data)
}
