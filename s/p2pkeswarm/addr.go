package p2pkeswarm

import (
	"bytes"
	"fmt"

	"github.com/brendoncarroll/go-p2p"
	"github.com/pkg/errors"
)

type Addr[T p2p.Addr] struct {
	ID   p2p.PeerID
	Addr T
}

func (a Addr[T]) String() string {
	data, _ := a.MarshalText()
	return string(data)
}

func (a Addr[T]) MarshalText() ([]byte, error) {
	data, err := a.Addr.MarshalText()
	if err != nil {
		return nil, err
	}
	s := fmt.Sprintf("%s@%s", a.ID.String(), string(data))
	return []byte(s), nil
}

func (a Addr[T]) Unwrap() p2p.Addr {
	return a.Addr
}

func (a Addr[T]) Map(fn func(T) T) Addr[T] {
	return Addr[T]{
		ID:   a.ID,
		Addr: fn(a.Addr),
	}
}

func (a Addr[T]) GetPeerID() p2p.PeerID {
	return a.ID
}

func ParseAddr[T p2p.Addr](inner p2p.AddrParser[T], data []byte) (*Addr[T], error) {
	parts := bytes.SplitN(data, []byte("@"), 2)
	if len(parts) < 2 {
		return nil, errors.Errorf("no @ in addr")
	}
	id := p2p.PeerID{}
	if err := id.UnmarshalText(parts[0]); err != nil {
		return nil, err
	}
	addr, err := inner(parts[1])
	if err != nil {
		return nil, err
	}
	return &Addr[T]{
		ID:   id,
		Addr: *addr,
	}, nil
}

func (s *Swarm[T]) ParseAddr(data []byte) (*Addr[T], error) {
	return ParseAddr(s.inner.ParseAddr, data)	
}