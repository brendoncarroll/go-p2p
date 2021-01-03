package upnpswarm

import (
	"net"

	"github.com/brendoncarroll/go-p2p"
)

type HasTCP interface {
	GetTCP() net.TCPAddr
	MapTCP(func(net.TCPAddr) net.TCPAddr) p2p.Addr
}

type HasUDP interface {
	GetUDP() net.UDPAddr
	MapUDP(func(net.UDPAddr) net.UDPAddr) p2p.Addr
}

func ExtractTCP(x p2p.Addr) *net.TCPAddr {
	if x, ok := x.(HasTCP); ok {
		a := x.GetTCP()
		return &a
	}
	if x, ok := x.(p2p.UnwrapAddr); ok {
		a := x.Unwrap()
		return ExtractTCP(a)
	}
	return nil
}

func MapTCP(x p2p.Addr, fn func(net.TCPAddr) net.TCPAddr) p2p.Addr {
	if x, ok := x.(HasTCP); ok {
		return x.MapTCP(fn)
	}
	if x, ok := x.(p2p.UnwrapAddr); ok {
		a := x.Unwrap()
		return MapTCP(a, fn)
	}
	return x
}

func ExtractUDP(x p2p.Addr) *net.UDPAddr {
	if x, ok := x.(HasUDP); ok {
		a := x.GetUDP()
		return &a
	}
	if x, ok := x.(p2p.UnwrapAddr); ok {
		a := x.Unwrap()
		return ExtractUDP(a)
	}
	return nil
}

func MapUDP(x p2p.Addr, fn func(net.UDPAddr) net.UDPAddr) p2p.Addr {
	if x, ok := x.(HasUDP); ok {
		return x.MapUDP(fn)
	}
	if x, ok := x.(p2p.UnwrapAddr); ok {
		a := x.Unwrap()
		return MapUDP(a, fn)
	}
	return x
}
