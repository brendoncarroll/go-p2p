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
)

var (
	log = p2p.Logger

	_ p2p.SecureSwarm    = &swarm{}
	_ p2p.SecureAskSwarm = &askSwarm{}
)

type Swarm interface {
	p2p.SecureSwarm
	TellPeer(ctx context.Context, dst p2p.PeerID, data []byte) error
}

type swarm struct {
	s        p2p.SecureSwarm
	localID  p2p.PeerID
	getAddrs AddrSource

	mu        sync.RWMutex
	lastAddrs map[p2p.PeerID]p2p.Addr
}

func NewSwarm(s p2p.SecureSwarm, addrSource AddrSource) Swarm {
	return newSwarm(s, addrSource)
}

func newSwarm(s p2p.SecureSwarm, addrSource AddrSource) *swarm {
	pubKey := s.PublicKey()
	return &swarm{
		s:         s,
		localID:   p2p.NewPeerID(pubKey),
		getAddrs:  addrSource,
		lastAddrs: make(map[p2p.PeerID]p2p.Addr),
	}
}

func (ps *swarm) Tell(ctx context.Context, addr p2p.Addr, data []byte) error {
	return ps.TellPeer(ctx, addr.(p2p.PeerID), data)
}

func (ps *swarm) TellPeer(ctx context.Context, dst p2p.PeerID, data []byte) error {
	var err error
	for _, addr := range ps.possibleAddrs(dst) {
		err = ps.s.Tell(ctx, addr, data)
		if err != nil {
			log.Errorf("error telling, marking offline %v", err)
			ps.markOffline(dst, addr)
			continue
		} else {
			ps.markOnline(dst, addr)
			return nil
		}
	}
	if err != nil {
		return err
	}
	return ErrPeerUnreachable
}

func (ps *swarm) OnTell(fn p2p.TellHandler) {
	ps.s.OnTell(func(m *p2p.Message) {
		peerID := p2p.NewPeerID(ps.s.LookupPublicKey(m.Src))
		ps.markOnline(peerID, m.Src)
		m.Src = peerID
		m.Dst = ps.localID
		fn(m)
	})
}

func (ps *swarm) Close() error {
	return ps.s.Close()
}

func (ps *swarm) MTU(ctx context.Context, addr p2p.Addr) int {
	return ps.s.MTU(ctx, addr)
}

func (ps *swarm) PublicKey() p2p.PublicKey {
	return ps.s.PublicKey()
}

func (ps *swarm) LookupPublicKey(addr p2p.Addr) p2p.PublicKey {
	id := addr.(p2p.PeerID)
	addrs := ps.getAddrs(id)
	if len(addrs) < 1 {
		return nil
	}
	return ps.s.LookupPublicKey(addrs[0])
}

func (ps *swarm) LocalAddrs() []p2p.Addr {
	return []p2p.Addr{ps.localID}
}

func (ps *swarm) LocalID() p2p.PeerID {
	return ps.localID
}

func (ps *swarm) ParseAddr(data []byte) (p2p.Addr, error) {
	id := p2p.PeerID{}
	if err := id.UnmarshalText(data); err != nil {
		return nil, err
	}
	return id, nil
}

func (ps *swarm) markOnline(id p2p.PeerID, addr p2p.Addr) {
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

func (ps *swarm) markOffline(id p2p.PeerID, addr p2p.Addr) {
	ps.mu.Lock()
	if addr2, exists := ps.lastAddrs[id]; exists && (addr2.Key() == addr.Key()) {
		delete(ps.lastAddrs, id)
	}
	ps.mu.Unlock()
}

func (ps *swarm) lastAddr(id p2p.PeerID) p2p.Addr {
	ps.mu.RLock()
	defer ps.mu.RUnlock()
	return ps.lastAddrs[id]
}

func (ps *swarm) possibleAddrs(dst p2p.PeerID) []p2p.Addr {
	addrs := make([]p2p.Addr, 0, 5)
	if addr := ps.lastAddr(dst); addr != nil {
		addrs = append(addrs, addr)
	}
	addrs = append(addrs, ps.getAddrs(dst)...)
	return addrs
}

type AskSwarm interface {
	p2p.SecureAskSwarm
	AskPeer(ctx context.Context, dst p2p.PeerID, data []byte) ([]byte, error)
}

type askSwarm struct {
	*swarm
	s p2p.SecureAskSwarm
}

func NewAskSwarm(s p2p.SecureAskSwarm, addrSource AddrSource) AskSwarm {
	return newAskSwarm(s, addrSource)
}

func newAskSwarm(s p2p.SecureAskSwarm, addrSource AddrSource) *askSwarm {
	return &askSwarm{
		swarm: newSwarm(s, addrSource),
		s:     s,
	}
}

func (ps *askSwarm) Ask(ctx context.Context, addr p2p.Addr, data []byte) ([]byte, error) {
	return ps.AskPeer(ctx, addr.(p2p.PeerID), data)
}

func (ps *askSwarm) AskPeer(ctx context.Context, dst p2p.PeerID, data []byte) ([]byte, error) {
	var err error
	var res []byte
	for _, addr := range ps.possibleAddrs(dst) {
		res, err = ps.s.Ask(ctx, addr, data)
		if err != nil {
			log.Error(err)
			ps.markOffline(dst, addr)
			continue
		} else {
			ps.markOnline(dst, addr)
			return res, nil
		}
	}
	if err != nil {
		return nil, err
	}
	return nil, ErrPeerUnreachable
}

func (ps *askSwarm) OnAsk(fn p2p.AskHandler) {
	ps.s.OnAsk(func(ctx context.Context, m *p2p.Message, w io.Writer) {
		peerID := p2p.NewPeerID(ps.s.LookupPublicKey(m.Src))
		ps.markOnline(peerID, m.Src)
		m.Src = peerID
		m.Dst = ps.localID
		fn(ctx, m, w)
	})
}
