package p2p

type Addr interface {
	Key() string
	MarshalText() ([]byte, error)
}

type UnwrapAddr interface {
	Unwrap() Addr
	Map(func(Addr) Addr) Addr
}
