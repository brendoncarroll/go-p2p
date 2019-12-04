package udpswarm

import (
	"context"
	"errors"
	"log"
	"net"

	"github.com/brendoncarroll/go-p2p"
)

const (
	IPv4MTU = 576
	IPv6MTU = 1280

	TheoreticalMTU = 1 << 16
)

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

// New creates a new UDP Swarm
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

func (s *Swarm) LocalAddr() p2p.Addr {
	laddr := s.conn.LocalAddr().(*net.UDPAddr)
	return (*Addr)(laddr)
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
		n, addr, err := s.conn.ReadFrom(buf)
		if err != nil {
			log.Println(err)
			return
		}
		uaddr := addr.(*net.UDPAddr)

		msg := &p2p.Message{
			Src:     (*Addr)(uaddr),
			Dst:     s.LocalAddr(),
			Payload: buf[:n],
		}
		s.handleTell(msg)
	}
}
