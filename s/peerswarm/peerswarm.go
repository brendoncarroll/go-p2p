package peerswarm

import (
	"context"
	"errors"
	"io"
	"sync"

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

	mu        sync.RWMutex
	lastAddrs map[p2p.PeerID]p2p.Addr
}

func NewSwarm(s p2p.SecureSwarm, addrSource AddrSource) *Swarm {
	pubKey := s.PublicKey()
	return &Swarm{
		s:         s,
		localID:   p2p.NewPeerID(pubKey),
		getAddrs:  addrSource,
		lastAddrs: make(map[p2p.PeerID]p2p.Addr),
	}
}

func (ps *Swarm) Tell(ctx context.Context, addr p2p.Addr, data []byte) error {
	return ps.TellPeer(ctx, addr.(p2p.PeerID), data)
}

func (ps *Swarm) TellPeer(ctx context.Context, dst p2p.PeerID, data []byte) error {
	for _, addr := range ps.possibleAddrs(dst) {
		err := ps.s.Tell(ctx, addr, data)
		if err != nil {
			log.Error(err)
			ps.markOffline(dst, addr)
			continue
		} else {
			ps.markOnline(dst, addr)
			return nil
		}
	}
	return ErrPeerUnreachable
}

func (ps *Swarm) OnTell(fn p2p.TellHandler) {
	ps.s.OnTell(func(m *p2p.Message) {
		peerID := p2p.NewPeerID(ps.s.LookupPublicKey(m.Src))
		ps.markOnline(peerID, m.Src)
		m.Src = peerID
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

func (ps *Swarm) markOnline(id p2p.PeerID, addr p2p.Addr) {
	ps.mu.RLock()
	addr2, exists := ps.lastAddrs[id]
	ps.mu.RUnlock()
	if exists && (addr2.Key() == addr.Key()) {
		return
	}

	ps.mu.Lock()
	ps.lastAddrs[id] = addr
	ps.mu.Unlock()
}

func (ps *Swarm) markOffline(id p2p.PeerID, addr p2p.Addr) {
	ps.mu.Lock()
	if addr2, exists := ps.lastAddrs[id]; exists && (addr2.Key() == addr.Key()) {
		delete(ps.lastAddrs, id)
	}
	ps.mu.Unlock()
}

func (ps *Swarm) lastAddr(id p2p.PeerID) p2p.Addr {
	ps.mu.RLock()
	defer ps.mu.RUnlock()
	return ps.lastAddrs[id]
}

func (ps *Swarm) possibleAddrs(dst p2p.PeerID) []p2p.Addr {
	addrs := make([]p2p.Addr, 0, 5)
	if addr := ps.lastAddr(dst); addr != nil {
		addrs = append(addrs, addr)
	}
	addrs = append(addrs, ps.getAddrs(dst)...)
	return addrs
}

type AskSwarm struct {
	*Swarm
	s p2p.SecureAskSwarm
}

func NewAskSwarm(s p2p.SecureAskSwarm, addrSource AddrSource) *AskSwarm {
	return &AskSwarm{
		Swarm: NewSwarm(s, addrSource),
		s:     s,
	}
}

func (ps *AskSwarm) Ask(ctx context.Context, addr p2p.Addr, data []byte) ([]byte, error) {
	return ps.Ask(ctx, addr.(p2p.PeerID), data)
}

func (ps *AskSwarm) AskPeer(ctx context.Context, dst p2p.PeerID, data []byte) ([]byte, error) {
	for _, addr := range ps.possibleAddrs(dst) {
		res, err := ps.s.Ask(ctx, addr, data)
		if err != nil {
			ps.markOffline(dst, addr)
			log.Error(err)
			continue
		} else {
			ps.markOnline(dst, addr)
			return res, nil
		}
	}
	return nil, ErrPeerUnreachable
}

func (ps *AskSwarm) OnAsk(fn p2p.AskHandler) {
	ps.s.OnAsk(func(ctx context.Context, m *p2p.Message, w io.Writer) {
		peerID := p2p.NewPeerID(ps.s.LookupPublicKey(m.Src))
		ps.markOnline(peerID, m.Src)
		m.Src = peerID
		m.Dst = ps.localID
		fn(ctx, m, w)
	})
}
