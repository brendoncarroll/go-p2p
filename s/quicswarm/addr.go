package quicswarm

import (
	"bytes"
	"fmt"

	"github.com/pkg/errors"

	"github.com/brendoncarroll/go-p2p"
)

var _ interface {
	p2p.Addr
	p2p.UnwrapAddr
} = &Addr{}

type Addr struct {
	ID   p2p.PeerID
	Addr p2p.Addr
}

func (a Addr) Key() string {
	data, _ := a.MarshalText()
	return string(data)
}

func (a Addr) String() string {
	return a.Key()
}

func (a Addr) MarshalText() ([]byte, error) {
	data, err := a.Addr.MarshalText()
	if err != nil {
		return nil, err
	}
	y := fmt.Sprintf("%s@%s", a.ID.String(), data)
	return []byte(y), nil
}

func (s *Swarm) ParseAddr(data []byte) (p2p.Addr, error) {
	return ParseAddr(s.inner, data)
}

func ParseAddr(inner p2p.Swarm, data []byte) (p2p.Addr, error) {
	parts := bytes.SplitN(data, []byte("@"), 2)
	if len(parts) < 2 {
		return nil, errors.Errorf("address must contain @")
	}
	a := Addr{}
	if err := a.ID.UnmarshalText(parts[0]); err != nil {
		return nil, err
	}
	innerAddr, err := inner.ParseAddr(parts[1])
	if err != nil {
		return nil, err
	}
	a.Addr = innerAddr
	return a, nil
}

func (a Addr) GetPeerID() p2p.PeerID {
	return a.ID
}

func (a Addr) Unwrap() p2p.Addr {
	return a.Addr
}

func (a Addr) Map(fn func(p2p.Addr) p2p.Addr) p2p.Addr {
	return &Addr{
		ID:   a.ID,
		Addr: fn(a.Addr),
	}
}

func (a Addr) Equals(b Addr) bool {
	return a.ID.Equals(b.ID) && p2p.CompareAddrs(a.Addr, b.Addr) == 0
}
