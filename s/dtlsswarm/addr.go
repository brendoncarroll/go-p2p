package dtlsswarm

import (
	"bytes"
	"net"

	"github.com/brendoncarroll/go-p2p"
	"github.com/brendoncarroll/go-p2p/s/natswarm"
)

type Addr struct {
	ID p2p.PeerID
	p2p.Addr
}

func (a Addr) Key() string {
	data, err := a.MarshalText()
	if err != nil {
		panic(err)
	}
	return string(data)
}

func (a Addr) MarshalText() ([]byte, error) {
	inner, err := a.Addr.MarshalText()
	if err != nil {
		return nil, err
	}
	idBytes, err := a.ID.MarshalText()
	if err != nil {
		return nil, err
	}
	buf := bytes.Buffer{}
	buf.Write(idBytes)
	buf.WriteByte('@')
	buf.Write(inner)

	return buf.Bytes(), nil
}

func (a Addr) String() string {
	return a.Key()
}

func (a Addr) GetIP() net.IP {
	if inner, ok := a.Addr.(p2p.HasIP); ok {
		return inner.GetIP()
	}
	return nil
}

func (a Addr) MapIP(x net.IP) p2p.Addr {
	if inner, ok := a.Addr.(p2p.MapIP); ok {
		return Addr{
			ID:   a.ID,
			Addr: inner.MapIP(x),
		}
	}
	return a
}

func (a Addr) GetUDP() net.UDPAddr {
	if inner, ok := a.Addr.(natswarm.HasUDP); ok {
		return inner.GetUDP()
	}
	return net.UDPAddr{}
}

func (a Addr) MapUDP(x net.UDPAddr) p2p.Addr {
	if inner, ok := a.Addr.(natswarm.HasUDP); ok {
		return Addr{
			ID:   a.ID,
			Addr: inner.MapUDP(x),
		}
	}
	return a
}
