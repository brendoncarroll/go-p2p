package udpswarm

import (
	"context"
	"errors"
	"net"
	"strings"

	"github.com/brendoncarroll/go-p2p"
)

const (
	IPv4MTU = 576
	IPv6MTU = 1280

	TheoreticalMTU = 1 << 16
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

	handleTell p2p.TellHandler
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
		conn:       conn,
		handleTell: p2p.NoOpTellHandler,
	}
	go s.loop()

	return s, nil
}

func (s *Swarm) OnTell(fn p2p.TellHandler) {
	s.handleTell = fn
}

func (s *Swarm) Tell(ctx context.Context, addr p2p.Addr, data []byte) error {
	a, ok := addr.(*Addr)
	if !ok {
		return errors.New("invalid address")
	}
	udpAddr, err := net.ResolveUDPAddr("", a.String())
	if err != nil {
		return err
	}
	_, err = s.conn.WriteTo(data, udpAddr)
	return err
}

func (s *Swarm) LocalAddrs() []p2p.Addr {
	laddr := s.conn.LocalAddr().(*net.UDPAddr)
	a := (*Addr)(laddr)
	return p2p.ExpandUnspecifiedIPs([]p2p.Addr{a})
}

func (s *Swarm) MTU(ctx context.Context, addr p2p.Addr) int {
	laddr := s.conn.LocalAddr().(*net.UDPAddr)
	if laddr.IP.To16() != nil {
		return IPv6MTU
	} else {
		return IPv4MTU
	}
}

func (s *Swarm) Close() error {
	return s.conn.Close()
}

func (s *Swarm) loop() {
	buf := make([]byte, TheoreticalMTU)
	for {
		n, addr, err := s.conn.ReadFromUDP(buf)
		if err != nil {
			if strings.Contains(err.Error(), "use of closed network connection") {
				return
			}
			log.Error(err)
			return
		}

		msg := &p2p.Message{
			Src:     (*Addr)(addr),
			Dst:     s.LocalAddrs()[0],
			Payload: buf[:n],
		}
		s.handleTell(msg)
	}
}
