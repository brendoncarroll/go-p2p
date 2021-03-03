package udpswarm

import (
	"context"
	"net"
	"strings"

	"github.com/brendoncarroll/go-p2p"
	"golang.org/x/sync/errgroup"
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
	conn       *net.UDPConn
	numWorkers int
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
	return s, nil
}

func (s *Swarm) ServeTells(fn p2p.TellHandler) error {
	eg := errgroup.Group{}
	for i := 0; i < s.numWorkers; i++ {
		eg.Go(func() error {
			return s.readLoop(fn)
		})
	}
	err := eg.Wait()
	if err == nil {
		err = p2p.ErrSwarmClosed
	}
	return err
}

func (s *Swarm) Tell(ctx context.Context, addr p2p.Addr, data p2p.IOVec) error {
	a := addr.(Addr)
	a2 := (net.UDPAddr)(a)
	_, err := s.conn.WriteToUDP(p2p.VecBytes(data), &a2)
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
	return s.conn.Close()
}

func (s *Swarm) readLoop(fn p2p.TellHandler) error {
	buf := make([]byte, TheoreticalMTU)
	for {
		n, udpAddr, err := s.conn.ReadFromUDP(buf)
		if err != nil {
			if strings.Contains(err.Error(), "use of closed network connection") {
				err = nil
			}
			return err
		}
		msg := &p2p.Message{
			Src:     (Addr)(*udpAddr),
			Dst:     s.LocalAddrs()[0],
			Payload: buf[:n],
		}
		fn(msg)
	}
}
