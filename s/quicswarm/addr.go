package quicswarm

import (
	"bytes"
	"fmt"

	"github.com/pkg/errors"
	"golang.org/x/crypto/sha3"

	"github.com/brendoncarroll/go-p2p"
	"github.com/brendoncarroll/go-p2p/f/x509"
)

type Fingerprinter = func(PublicKey) p2p.PeerID

func DefaultFingerprinter(x PublicKey) p2p.PeerID {
	data := x509.MarshalPublicKey(nil, &x)
	return sha3.Sum256(data)
}

type Addr[T p2p.Addr] struct {
	ID   p2p.PeerID
	Addr T
}

func (a Addr[T]) Key() string {
	data, _ := a.MarshalText()
	return string(data)
}

func (a Addr[T]) String() string {
	return a.Key()
}

func (a Addr[T]) MarshalText() ([]byte, error) {
	data, err := a.Addr.MarshalText()
	if err != nil {
		return nil, err
	}
	y := fmt.Sprintf("%s@%s", a.ID.String(), data)
	return []byte(y), nil
}

func ParseAddr[T p2p.Addr](inner p2p.AddrParser[T], data []byte) (Addr[T], error) {
	parts := bytes.SplitN(data, []byte("@"), 2)
	if len(parts) < 2 {
		return Addr[T]{}, errors.Errorf("address must contain @")
	}
	a := Addr[T]{}
	if err := a.ID.UnmarshalText(parts[0]); err != nil {
		return Addr[T]{}, err
	}
	innerAddr, err := inner(parts[1])
	if err != nil {
		return Addr[T]{}, err
	}
	a.Addr = innerAddr
	return a, nil
}

func (a Addr[T]) GetPeerID() p2p.PeerID {
	return a.ID
}

func (a Addr[T]) Unwrap() T {
	return a.Addr
}

func (a Addr[T]) Map(fn func(T) T) Addr[T] {
	return Addr[T]{
		ID:   a.ID,
		Addr: fn(a.Addr),
	}
}

func (a Addr[T]) Equals(b Addr[T]) bool {
	return (a.ID == b.ID) && p2p.CompareAddrs(a.Addr, b.Addr) == 0
}
