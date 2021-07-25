package udpswarm

import (
	"context"
	"net"

	"github.com/brendoncarroll/go-p2p"
)

const (
	IPv4MTU = 576
	IPv6MTU = 1280

	TheoreticalMTU = (1 << 16) - 1
)

var log = p2p.Logger

var _ interface {
	p2p.Swarm
} = &Swarm{}

/*
Swarm implements p2p.Swarm using the User Datagram Protocol

WARNING: This implementation is not secure. It does not encrypt
traffic, does not verify identity of peers, and (therefore) does
not implement p2p.SecureSwarm.

It is included as a transport for secure swarms to be built on.
*/
type Swarm struct {
	conn *net.UDPConn
}

func New(laddr string) (*Swarm, error) {
	udpAddr, err := net.ResolveUDPAddr("", laddr)
	if err != nil {
		return nil, err
	}
	conn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		return nil, err
	}
	s := &Swarm{
		conn: conn,
	}
	return s, nil
}

func (s *Swarm) Tell(ctx context.Context, addr p2p.Addr, data p2p.IOVec) error {
	a := addr.(Addr)
	a2 := (net.UDPAddr)(a)
	_, err := s.conn.WriteToUDP(p2p.VecBytes(nil, data), &a2)
	return err
}

func (s *Swarm) Receive(ctx context.Context, src, dst *p2p.Addr, buf []byte) (int, error) {
	n, udpAddr, err := s.conn.ReadFromUDP(buf)
	if err != nil {
		return 0, err
	}
	*src = Addr(*udpAddr)
	*dst = s.LocalAddrs()[0]
	return n, nil
}

func (s *Swarm) LocalAddrs() []p2p.Addr {
	laddr := s.conn.LocalAddr().(*net.UDPAddr)
	a := (*Addr)(laddr)
	return p2p.ExpandUnspecifiedIPs([]p2p.Addr{*a})
}

func (s *Swarm) MTU(ctx context.Context, addr p2p.Addr) int {
	laddr := s.conn.LocalAddr().(*net.UDPAddr)
	if laddr.IP.To16() != nil {
		return IPv6MTU
	}
	return IPv4MTU
}

func (s *Swarm) MaxIncomingSize() int {
	return TheoreticalMTU
}

func (s *Swarm) ParseAddr(x []byte) (p2p.Addr, error) {
	a := Addr{}
	if err := a.UnmarshalText(x); err != nil {
		return nil, err
	}
	return a, nil
}

func (s *Swarm) Close() error {
	return s.conn.Close()
}
