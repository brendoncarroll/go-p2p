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

var _ p2p.Swarm[Addr] = &Swarm{}

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

func (s *Swarm) Tell(ctx context.Context, a Addr, data p2p.IOVec) error {
	if p2p.VecSize(data) > s.MTU(ctx, a) {
		return p2p.ErrMTUExceeded
	}
	a2 := a.AsNetAddr()
	_, err := s.conn.WriteToUDP(p2p.VecBytes(nil, data), &a2)
	return err
}

func (s *Swarm) Receive(ctx context.Context, th func(p2p.Message[Addr])) error {
	buf := [TheoreticalMTU]byte{}
	n, remoteAddr, err := s.conn.ReadFromUDP(buf[:])
	if err != nil {
		return err
	}
	th(p2p.Message[Addr]{
		Src:     FromNetAddr(*remoteAddr),
		Dst:     FromNetAddr(*s.conn.LocalAddr().(*net.UDPAddr)),
		Payload: buf[:n],
	})
	return nil
}

func (s *Swarm) LocalAddrs() []Addr {
	laddr := s.conn.LocalAddr().(*net.UDPAddr)
	return p2p.ExpandUnspecifiedIPs([]Addr{FromNetAddr(*laddr)})
}

func (s *Swarm) MTU(ctx context.Context, addr Addr) int {
	laddr := s.conn.LocalAddr().(*net.UDPAddr)
	if laddr.IP.To16() != nil {
		return IPv6MTU
	}
	return IPv4MTU
}

func (s *Swarm) MaxIncomingSize() int {
	return TheoreticalMTU
}

func (s *Swarm) ParseAddr(x []byte) (Addr, error) {
	return ParseAddr(x)
}

func (s *Swarm) Close() error {
	return s.conn.Close()
}
