package aggswarm

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	mrand "math/rand"
	"sync"

	"github.com/brendoncarroll/go-p2p"
)

type Transport interface {
	p2p.SecureSwarm
	p2p.Swarm
}

/*
	Swarm aggregates multiple connections by PeerIDs.
*/
type Swarm struct {
	transports  map[string]Transport
	localPubKey p2p.PublicKey

	mu       sync.RWMutex
	n        int
	edges    map[int]Edge
	key2Edge map[string]int
	id2Edge  map[PeerID][]int

	handleAsk  p2p.AskHandler
	handleTell p2p.TellHandler
}

func New(privKey p2p.PrivateKey, transports map[string]Transport) *Swarm {
	pubKey := privKey.Public()
	localID := p2p.NewPeerID(pubKey)
	s := &Swarm{
		transports:  transports,
		localPubKey: pubKey,

		n: 1,

		edges:    map[int]Edge{},
		key2Edge: map[string]int{},
		id2Edge:  map[PeerID][]int{},

		handleAsk:  p2p.NoOpAskHandler,
		handleTell: p2p.NoOpTellHandler,
	}

	// set up handlers
	for tname, t := range transports {
		lid := p2p.NewPeerID(t.PublicKey())
		if localID != lid {
			log.Println(localID, lid)
			panic("transports must use same public key")
		}
		tname := tname
		t.OnTell(func(msg *p2p.Message) {
			e := s.getEdge(tname, msg.Src)
			msg.Src = &e
			msg.Dst = s.dstEdge(e)
			s.handleTell(msg)
		})
		if at, ok := t.(p2p.Asker); ok {
			at.OnAsk(func(ctx context.Context, req *p2p.Message, w io.Writer) {
				e := s.getEdge(tname, req.Src)
				req.Src = &e
				req.Dst = s.dstEdge(e)
				s.handleAsk(ctx, req, w)
			})
		}
	}

	return s
}

func (s *Swarm) OnAsk(fn p2p.AskHandler) {
	if fn == nil {
		fn = p2p.NoOpAskHandler
	}
	s.handleAsk = fn
}

func (s *Swarm) OnTell(fn p2p.TellHandler) {
	if fn == nil {
		fn = p2p.NoOpTellHandler
	}
	s.handleTell = fn
}

func (s *Swarm) Ask(ctx context.Context, addr p2p.Addr, data []byte) ([]byte, error) {
	e := addr.(*Edge)
	if err := e.fixAddr(s); err != nil {
		return nil, err
	}
	raddr, err := s.lookupEdge(e)
	if err != nil {
		return nil, err
	}
	t, exists := s.transports[raddr.Transport]
	if !exists {
		return nil, errors.New("transport does not exist")
	}
	at, ok := t.(p2p.Asker)
	if !ok {
		return nil, fmt.Errorf("transport %v does not support asking", t)
	}
	return at.Ask(ctx, raddr.Addr, data)
}

func (s *Swarm) Tell(ctx context.Context, addr p2p.Addr, data []byte) error {
	e := addr.(*Edge)
	if err := e.fixAddr(s); err != nil {
		return err
	}
	raddr, err := s.lookupEdge(e)
	if err != nil {
		return err
	}
	t, exists := s.transports[raddr.Transport]
	if !exists {
		return errors.New("transport does not exist")
	}
	return t.Tell(ctx, raddr.Addr, data)
}

func (s *Swarm) lookupEdge(x *Edge) (*Edge, error) {
	switch {
	case x.Index > 0:
		return s.getByIndex(x.Index)
	case !x.PeerID.Equals(p2p.ZeroPeerID()):
		return s.getByPeer(x.PeerID, x.Transport)
	default:
		return x, nil
	}
}

func (s *Swarm) getByIndex(index int) (*Edge, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	raddr, exists := s.edges[index]
	if !exists {
		return nil, errors.New("no edge with that index")
	}
	return &raddr, nil
}

func (s *Swarm) getByPeer(id p2p.PeerID, t string) (*Edge, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	edges, exists := s.id2Edge[id]
	if !exists {
		return nil, errors.New("no edges for peer")
	}

	if t == "" {
		i := mrand.Intn(len(s.edges))
		raddr, exists := s.edges[i]
		if !exists {
			panic("index referred to non existant edge")
		}
		return &raddr, nil
	}

	// find one for the right transport
	for _, edge := range edges {
		raddr, exists := s.edges[edge]
		if !exists {
			panic("index referred to non existant edge")
		}
		if raddr.Transport == t {
			return &raddr, nil
		}
	}

	return nil, errors.New("could not find a connection")
}

func (s *Swarm) LocalAddrs() []p2p.Addr {
	ret := []p2p.Addr{}
	for tname, t := range s.transports {
		for _, laddr := range t.LocalAddrs() {
			edge := &Edge{
				PeerID:    s.LocalID(),
				Transport: tname,
				Addr:      laddr,
			}
			ret = append(ret, edge)
		}
	}
	return ret
}

func (s *Swarm) MTU(ctx context.Context, addr p2p.Addr) int {
	e := addr.(*Edge)
	e, err := s.lookupEdge(e)
	if err != nil {
		return 0
	}
	return s.transports[e.Transport].MTU(ctx, e.Addr)
}

func (s *Swarm) Close() error {
	errs := []error{}
	for _, t := range s.transports {
		err := t.Close()
		errs = append(errs, err)
	}
	return nil
}

func (s *Swarm) LocalID() p2p.PeerID {
	return p2p.NewPeerID(s.localPubKey)
}

func (s *Swarm) getEdge(tname string, addr p2p.Addr) Edge {
	s.mu.RLock()
	index, exists := s.key2Edge[Edge{Transport: tname, Addr: addr}.Key()]
	if exists {
		s.mu.RUnlock()
		return s.edges[index]
	}
	s.mu.RUnlock()

	s.mu.Lock()
	// get index
	n := s.n
	s.n++

	// get id
	pubKey := s.transports[tname].LookupPublicKey(addr)
	id := p2p.NewPeerID(pubKey)

	// create edge
	e := Edge{
		PeerID:    id,
		Index:     n,
		Transport: tname,
		Addr:      addr,
	}

	// add to indexes
	s.edges[n] = e
	s.key2Edge[e.Key()] = n
	s.id2Edge[id] = append(s.id2Edge[id], n)
	s.mu.Unlock()

	return e
}

func (s *Swarm) dstEdge(x Edge) *Edge {
	y := &Edge{
		PeerID:    s.LocalID(),
		Index:     x.Index,
		Transport: x.Transport,
		Addr:      s.transports[x.Transport].LocalAddrs()[0],
	}
	return y
}

func (s *Swarm) deleteEdge(i int) {
	s.mu.Lock()
	defer s.mu.Unlock()

	e, exists := s.edges[i]
	if !exists {
		return
	}

	s.id2Edge[e.PeerID] = removeInt(s.id2Edge[e.PeerID], i)
	delete(s.key2Edge, e.Key())
	delete(s.edges, i)
}

func removeInt(slice []int, x int) []int {
	removed := 0
	for i := range slice {
		if slice[i] == x {
			removed++
		} else {
			slice[i-removed] = slice[i]
		}
	}
	return slice[:len(slice)-removed]
}
