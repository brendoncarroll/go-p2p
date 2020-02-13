package peerswarm

import (
	"context"
	"errors"
	"io"

	"github.com/brendoncarroll/go-p2p"
)

type AddrSource func(p2p.PeerID) []p2p.Addr

var (
	ErrPeerUnreachable = errors.New("peer unreachable")

	log = p2p.Logger

	_ p2p.SecureSwarm    = &Swarm{}
	_ p2p.SecureAskSwarm = &AskSwarm{}
)

type Swarm struct {
	s        p2p.SecureSwarm
	localID  p2p.PeerID
	getAddrs AddrSource
}

type AskSwarm struct {
	*Swarm
	s p2p.SecureAskSwarm
}

func NewSwarm(s p2p.SecureSwarm, addrSource AddrSource) *Swarm {
	pubKey := s.PublicKey()
	return &Swarm{
		s:        s,
		localID:  p2p.NewPeerID(pubKey),
		getAddrs: addrSource,
	}
}

func NewAskSwarm(s p2p.SecureAskSwarm, addrSource AddrSource) *AskSwarm {
	return &AskSwarm{
		Swarm: NewSwarm(s, addrSource),
		s:     s,
	}
}

func (ps *Swarm) Tell(ctx context.Context, addr p2p.Addr, data []byte) error {
	return ps.Tell(ctx, addr.(p2p.PeerID), data)
}

func (ps *Swarm) TellPeer(ctx context.Context, dst p2p.PeerID, data []byte) error {
	for _, addr := range ps.getAddrs(dst) {
		err := ps.s.Tell(ctx, addr, data)
		if err != nil {
			log.Error(err)
			continue
		} else {
			return nil
		}
	}
	return ErrPeerUnreachable
}

func (ps *Swarm) OnTell(fn p2p.TellHandler) {
	ps.s.OnTell(func(m *p2p.Message) {
		m.Src = p2p.NewPeerID(ps.s.LookupPublicKey(m.Src))
		m.Dst = ps.localID
		fn(m)
	})
}

func (ps *Swarm) Close() error {
	return ps.s.Close()
}

func (ps *Swarm) MTU(ctx context.Context, addr p2p.Addr) int {
	return ps.s.MTU(ctx, addr)
}

func (ps *Swarm) PublicKey() p2p.PublicKey {
	return ps.PublicKey()
}

func (ps *Swarm) LookupPublicKey(addr p2p.Addr) p2p.PublicKey {
	id := addr.(p2p.PeerID)
	addrs := ps.getAddrs(id)
	if len(addrs) < 1 {
		return nil
	}
	return ps.s.LookupPublicKey(addrs[0])
}

func (ps *Swarm) LocalAddrs() []p2p.Addr {
	return []p2p.Addr{ps.localID}
}

func (ps *Swarm) LocalID() p2p.PeerID {
	return ps.localID
}

func (ps *Swarm) ParseAddr(data []byte) (p2p.Addr, error) {
	id := p2p.PeerID{}
	if err := id.UnmarshalText(data); err != nil {
		return nil, err
	}
	return id, nil
}

func (ps *AskSwarm) Ask(ctx context.Context, addr p2p.Addr, data []byte) ([]byte, error) {
	return ps.Ask(ctx, addr.(p2p.PeerID), data)
}

func (ps *AskSwarm) AskPeer(ctx context.Context, dst p2p.PeerID, data []byte) ([]byte, error) {
	for _, addr := range ps.getAddrs(dst) {
		res, err := ps.s.Ask(ctx, addr, data)
		if err != nil {
			log.Error(err)
			continue
		} else {
			return res, nil
		}
	}
	return nil, ErrPeerUnreachable
}

func (ps *AskSwarm) OnAsk(fn p2p.AskHandler) {
	ps.s.OnAsk(func(ctx context.Context, m *p2p.Message, w io.Writer) {
		m.Src = p2p.NewPeerID(ps.s.LookupPublicKey(m.Src))
		m.Dst = ps.localID
		fn(ctx, m, w)
	})
}
