package httpswarm

import (
	"bytes"
	"net"
	"strconv"

	"github.com/brendoncarroll/go-p2p"
)

type Addr struct {
	IP   net.IP
	Port int
}

func (a Addr) MarshalText() ([]byte, error) {
	buf := bytes.Buffer{}
	buf.WriteString(a.IP.String())
	buf.WriteString(":")
	buf.WriteString(strconv.Itoa(a.Port))

	return buf.Bytes(), nil
}

func (a Addr) Key() string {
	data, _ := a.MarshalText()
	return string(data)
}

func (a Addr) HasIP() net.IP {
	return a.IP
}

func (a Addr) MapIP(x net.IP) p2p.Addr {
	return Addr{
		IP:   x,
		Port: a.Port,
	}
}

func (a Addr) GetTCP() net.TCPAddr {
	return net.TCPAddr{
		IP:   a.IP,
		Port: a.Port,
	}
}

func (a Addr) MapTCP(x net.TCPAddr) p2p.Addr {
	return Addr{
		IP:   x.IP,
		Port: x.Port,
	}
}
