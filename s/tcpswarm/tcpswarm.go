package tcpswarm

import (
	"net"
	"sync"
)

type Swarm struct {
	l     *net.TCPListener
	conns sync.Map
}

func New(laddr string) (*Swarm, error) {
	l, err := net.Listen("tcp", laddr)
	if err != nil {
		return nil, err
	}

	return &Swarm{
		l: l.(*net.TCPListener),
	}, nil
}

func (s *Swarm) Tell(ctx context.Context, addr p2p.Addr)
