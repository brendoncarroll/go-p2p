package p2p

import "strings"

type Addr interface {
	Key() string
	MarshalText() ([]byte, error)
}

type UnwrapAddr interface {
	Unwrap() Addr
	Map(func(Addr) Addr) Addr
}

func CompareAddrs(a, b Addr) int {
	return strings.Compare(a.Key(), b.Key())
}
