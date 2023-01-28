package p2p

import (
	"bytes"
)

// ComparableAddr is an Addr which also satisfies comparable
type ComparableAddr interface {
	Addr
	comparable
}

type Addr interface {
	// MarshalText serializes the address in a way that can be unambiguously parsed by the Swarm
	// that produced this address.
	MarshalText() ([]byte, error)

	String() string
}

// AddrParser is the type of functions which parse []byte into Addrs
type AddrParser[A Addr] func([]byte) (A, error)

type UnwrapAddr interface {
	Unwrap() Addr
	Map(func(Addr) Addr) Addr
}

func CompareAddrs(a, b Addr) int {
	aData, err := a.MarshalText()
	if err != nil {
		panic(err)
	}
	bData, err := b.MarshalText()
	if err != nil {
		panic(err)
	}
	return bytes.Compare(aData, bData)
}
