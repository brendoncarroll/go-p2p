package quicswarm

import (
	"fmt"
	"net"
	"regexp"
	"strconv"

	"github.com/pkg/errors"

	"github.com/brendoncarroll/go-p2p"
)

var _ p2p.HasIP = &Addr{}
var _ p2p.MapIP = &Addr{}

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

var addrRe = regexp.MustCompile(`^([A-z0-9\-_]+)@([0-9a-fA-F\.:]+):([0-9]+)$`)

func (s *Swarm) ParseAddr(data []byte) (p2p.Addr, error) {
	a := &Addr{}
	groups := addrRe.FindSubmatch(data)
	if len(groups) != 4 {
		return nil, errors.Errorf("could not parse quic addr %s", string(data))
	}
	if err := a.ID.UnmarshalText(groups[1]); err != nil {
		return nil, err
	}
	if ip := net.ParseIP(string(groups[2])); ip == nil {
		return nil, errors.Errorf("could not parse ip from %s", groups[2])
	} else {
		a.IP = ip
	}
	if a.IP.To4() != nil {
		a.IP = a.IP.To4()
	}
	port, err := strconv.Atoi(string(groups[3]))
	if err != nil {
		return nil, errors.Wrapf(err, "error parsing port")
	}
	if port == 0 {
		return nil, errors.New("invalid port")
	}
	a.Port = port
	return a, nil
}

func (a *Addr) GetPeerID() p2p.PeerID {
	return a.ID
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

func (a *Addr) GetIP() net.IP {
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
