package natswarm

import (
	"net"

	"github.com/brendoncarroll/go-p2p"
)

type HasTCP interface {
	GetTCP() net.TCPAddr
	MapTCP(net.TCPAddr) p2p.Addr
}

type HasUDP interface {
	GetUDP() net.UDPAddr
	MapUDP(net.UDPAddr) p2p.Addr
}
