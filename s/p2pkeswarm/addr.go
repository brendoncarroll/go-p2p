package p2pkeswarm

import (
	"bytes"
	"fmt"

	"github.com/brendoncarroll/go-p2p"
	"github.com/pkg/errors"
)

type Addr struct {
	ID   p2p.PeerID
	Addr p2p.Addr
}

func (a Addr) String() string {
	data, _ := a.MarshalText()
	return string(data)
}

func (a Addr) MarshalText() ([]byte, error) {
	data, err := a.Addr.MarshalText()
	if err != nil {
		return nil, err
	}
	s := fmt.Sprintf("%s@%s", a.ID.String(), string(data))
	return []byte(s), nil
}

func (a Addr) Unwrap() p2p.Addr {
	return a.Addr
}

func (a Addr) Map(fn func(p2p.Addr) p2p.Addr) Addr {
	return Addr{
		ID:   a.ID,
		Addr: fn(a.Addr),
	}
}

func (a Addr) GetPeerID() p2p.PeerID {
	return a.ID
}

func (s *Swarm) ParseAddr(data []byte) (p2p.Addr, error) {
	parts := bytes.SplitN(data, []byte("@"), 2)
	if len(parts) < 2 {
		return nil, errors.Errorf("no @ in addr")
	}
	id := p2p.PeerID{}
	if err := id.UnmarshalText(parts[0]); err != nil {
		return nil, err
	}
	addr, err := s.inner.ParseAddr(parts[1])
	if err != nil {
		return nil, err
	}
	return Addr{
		ID:   id,
		Addr: addr,
	}, nil
}
