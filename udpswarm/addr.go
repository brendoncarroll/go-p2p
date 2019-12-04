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
		fmt.Errorf("could not parse ip from: %s", host)
	}
	return err
}

func (a *Addr) MarshalText() ([]byte, error) {
	return []byte(a.String()), nil
}

func (a Addr) Key() string {
	return a.String()
}
