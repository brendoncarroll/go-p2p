package udpswarm

import (
	"fmt"
	"net"
	"net/netip"
)

type Addr struct {
	IP   netip.Addr
	Port uint16
}

func FromNetAddr(x net.UDPAddr) Addr {
	ip, ok := netip.AddrFromSlice(x.IP)
	if !ok {
		panic(ip)
	}
	return Addr{
		IP:   ip,
		Port: uint16(x.Port),
	}
}

func (a Addr) AsNetAddr() net.UDPAddr {
	return net.UDPAddr{
		IP:   a.IP.AsSlice(),
		Port: int(a.Port),
	}
}

func (a Addr) Network() string {
	a2 := a.AsNetAddr()
	return a2.Network()
}

func (a Addr) String() string {
	return fmt.Sprintf("%s:%d", a.IP.String(), a.Port)
}

func (a *Addr) UnmarshalText(x []byte) error {
	host, port, err := net.SplitHostPort(string(x))
	if err != nil {
		return err
	}
	if _, err = fmt.Sscan(port, &a.Port); err != nil {
		return err
	}
	a.IP, err = netip.ParseAddr(host)
	if err != nil {
		return fmt.Errorf("could not parse ip from: %s, %v", host, err)
	}
	return nil
}

func (a Addr) MarshalText() ([]byte, error) {
	return []byte(a.String()), nil
}

func (a Addr) Key() string {
	return a.String()
}

func (a Addr) GetIP() netip.Addr {
	return a.IP
}

func (a Addr) MapIP(fn func(netip.Addr) netip.Addr) Addr {
	return Addr{
		IP:   fn(a.IP),
		Port: a.Port,
	}
}

func ParseAddr(x []byte) (Addr, error) {
	var addr Addr
	err := addr.UnmarshalText(x)
	return addr, err
}
