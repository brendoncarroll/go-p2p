package p2p

import "net"

type HasTCP interface {
	GetTCP() net.TCPAddr
	MapTCP(func(net.TCPAddr) net.TCPAddr) Addr
}

type HasUDP interface {
	GetUDP() net.UDPAddr
	MapUDP(func(net.UDPAddr) net.UDPAddr) Addr
}

func ExtractTCP(x Addr) *net.TCPAddr {
	if x, ok := x.(HasTCP); ok {
		a := x.GetTCP()
		return &a
	}
	if x, ok := x.(UnwrapAddr); ok {
		a := x.Unwrap()
		return ExtractTCP(a)
	}
	return nil
}

func MapTCP(x Addr, fn func(net.TCPAddr) net.TCPAddr) Addr {
	if x, ok := x.(HasTCP); ok {
		return x.MapTCP(fn)
	}
	if x, ok := x.(UnwrapAddr); ok {
		return x.Map(func(inner Addr) Addr {
			return MapTCP(inner, fn)
		})
	}
	return x
}

func ExtractUDP(x Addr) *net.UDPAddr {
	if x, ok := x.(HasUDP); ok {
		a := x.GetUDP()
		return &a
	}
	if x, ok := x.(UnwrapAddr); ok {
		a := x.Unwrap()
		return ExtractUDP(a)
	}
	return nil
}

func MapUDP(x Addr, fn func(net.UDPAddr) net.UDPAddr) Addr {
	if x, ok := x.(HasUDP); ok {
		return x.MapUDP(fn)
	}
	if x, ok := x.(UnwrapAddr); ok {
		return x.Map(func(inner Addr) Addr {
			return MapUDP(inner, fn)
		})
	}
	return x
}
