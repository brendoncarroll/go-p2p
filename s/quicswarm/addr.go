package quicswarm

import (
	"errors"
	"fmt"
	"net"

	"github.com/brendoncarroll/go-p2p"
)

type Addr struct {
	ID   p2p.PeerID
	IP   net.IP
	Port int
}

func (a *Addr) Key() string {
	data, _ := a.MarshalText()
	return string(data)
}

func (a *Addr) MarshalText() ([]byte, error) {
	if a.Port < 0 {
		panic("invalid port")
	}

	y := fmt.Sprintf("%s@%s:%d", a.ID.String(), a.IP.String(), a.Port)
	return []byte(y), nil
}

func (a *Addr) UnmarshalText(data []byte) error {
	panic("not implemented")

	if a.Port < 0 {
		return errors.New("invalid port")
	}
	return nil
}

func (a *Addr) GetUDP() net.UDPAddr {
	return net.UDPAddr{
		IP:   a.IP,
		Port: a.Port,
	}
}

func (a *Addr) MapUDP(x net.UDPAddr) p2p.Addr {
	a2 := *a
	a2.IP = x.IP
	a2.Port = x.Port
	return &a2
}

func (a Addr) GetIP() net.IP {
	return a.IP
}

func (a *Addr) MapIP(x net.IP) p2p.Addr {
	a2 := *a
	a2.IP = x
	return &a2
}

func (a *Addr) Equals(b *Addr) bool {
	switch {
	case a == nil && b == nil:
		return true
	case a == nil || b == nil:
		return false
	default:
		eq := a.ID == b.ID &&
			a.IP.Equal(b.IP) &&
			a.Port == b.Port
		return eq
	}
}
