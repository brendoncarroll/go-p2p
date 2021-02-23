package udpswarm

import (
	"context"
	"net"
	"strings"

	"github.com/brendoncarroll/go-p2p"
	"github.com/brendoncarroll/go-p2p/s/swarmutil"
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
	conn       *net.UDPConn
	numWorkers int

	thCell swarmutil.THCell
}

func New(laddr string, opts ...Option) (*Swarm, error) {
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
		numWorkers: defaultNumWorkers,
	}
	for _, opt := range opts {
		opt(s)
	}
	for i := 0; i < s.numWorkers; i++ {
		go s.loop()
	}
	return s, nil
}

func (s *Swarm) OnTell(fn p2p.TellHandler) {
	s.thCell.Set(fn)
}

func (s *Swarm) Tell(ctx context.Context, addr p2p.Addr, data []byte) error {
	a := addr.(Addr)
	a2 := (net.UDPAddr)(a)
	_, err := s.conn.WriteToUDP(data, &a2)
	return err
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

func (s *Swarm) ParseAddr(x []byte) (p2p.Addr, error) {
	a := Addr{}
	if err := a.UnmarshalText(x); err != nil {
		return nil, err
	}
	return a, nil
}

func (s *Swarm) Close() error {
	s.OnTell(nil)
	return s.conn.Close()
}

func (s *Swarm) loop() {
	buf := make([]byte, TheoreticalMTU)
	for {
		n, udpAddr, err := s.conn.ReadFromUDP(buf)
		if err != nil {
			if strings.Contains(err.Error(), "use of closed network connection") {
				return
			}
			log.Error(err)
			return
		}
		msg := &p2p.Message{
			Src:     (Addr)(*udpAddr),
			Dst:     s.LocalAddrs()[0],
			Payload: buf[:n],
		}
		s.thCell.Handle(msg)
	}
}
