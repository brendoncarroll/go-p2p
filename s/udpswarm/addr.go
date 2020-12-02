package udpswarm

import (
	"fmt"
	"net"

	"github.com/brendoncarroll/go-p2p"
)

var _ interface {
	p2p.HasIP
} = &Addr{}

type Addr net.UDPAddr

func (a Addr) Network() string {
	a2 := net.UDPAddr(a)
	return a2.Network()
}

func (a Addr) String() string {
	return fmt.Sprintf("%s:%d", a.IP.String(), a.Port)
}

func (s *Swarm) ParseAddr(x []byte) (p2p.Addr, error) {
	a := &Addr{}
	host, port, err := net.SplitHostPort(string(x))
	if err != nil {
		return nil, err
	}
	if _, err = fmt.Sscan(port, &a.Port); err != nil {
		return nil, err
	}
	a.IP = net.ParseIP(host)
	if a.IP == nil {
		return nil, fmt.Errorf("could not parse ip from: %s", host)
	}
	if a.IP.To4() != nil {
		a.IP = a.IP.To4()
	}
	return a, nil
}

func (a Addr) MarshalText() ([]byte, error) {
	return []byte(a.String()), nil
}

func (a Addr) Key() string {
	return a.String()
}

func (a Addr) GetIP() net.IP {
	return a.IP
}

func (a Addr) MapIP(x net.IP) p2p.Addr {
	a2 := a
	a2.IP = x
	return &a2
}

func (a Addr) GetUDP() net.UDPAddr {
	return (net.UDPAddr)(a)
}

func (a Addr) MapUDP(x net.UDPAddr) p2p.Addr {
	a2 := (Addr)(x)
	return &a2
}
