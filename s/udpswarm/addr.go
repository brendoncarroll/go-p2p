package udpswarm

import (
	"fmt"
	"net"
)

type Addr net.UDPAddr

func (a Addr) Network() string {
	a2 := net.UDPAddr(a)
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
	a.IP = net.ParseIP(host)
	if a.IP == nil {
		return fmt.Errorf("could not parse ip from: %s", host)
	}
	if a.IP.To4() != nil {
		a.IP = a.IP.To4()
	}
	return nil
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

func (a Addr) MapIP(fn func(net.IP) net.IP) Addr {
	return Addr{
		IP:   fn(a.IP),
		Port: a.Port,
	}
}

func ParseAddr(x []byte) (*Addr, error) {
	var addr Addr
	if err := addr.UnmarshalText(x); err != nil {
		return nil, err
	}
	return &addr, nil
}
