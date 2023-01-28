package p2pconn

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/brendoncarroll/go-p2p"
)

// NewPacketConn turns a Swarm into a net.PacketConn
// Asks are not served, if you have an ask swarm you will need to handle or discard asks
// separately
func NewPacketConn[A p2p.Addr](s p2p.Swarm[A]) net.PacketConn {
	return &packetConn[A]{
		swarm: s,
	}
}

type packetConn[A p2p.Addr] struct {
	swarm p2p.Swarm[A]

	mu                          sync.Mutex
	readDeadline, writeDeadline *time.Time
}

func (c *packetConn[A]) WriteTo(p []byte, to net.Addr) (int, error) {
	target := to.(Addr[A])
	ctx, cf := c.getWriteContext()
	defer cf()
	if err := c.swarm.Tell(ctx, target.Addr, p2p.IOVec{p}); err != nil {
		return 0, err
	}
	return len(p), nil
}

func (c *packetConn[A]) ReadFrom(p []byte) (n int, from net.Addr, err error) {
	ctx, cf := c.getReadContext()
	defer cf()
	if err := c.swarm.Receive(ctx, func(m p2p.Message[A]) {
		from = Addr[A]{Swarm: c.swarm, Addr: m.Src}
		n = copy(p, m.Payload)
	}); err != nil {
		return 0, nil, err
	}
	return n, from, nil
}

func (c *packetConn[A]) LocalAddr() net.Addr {
	return Addr[A]{
		Addr:  c.swarm.LocalAddrs()[0],
		Swarm: c.swarm,
	}
}

func (c *packetConn[A]) SetDeadline(t time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.readDeadline = &t
	c.writeDeadline = &t
	return nil
}

func (c *packetConn[A]) SetReadDeadline(t time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.readDeadline = &t
	return nil
}

func (c *packetConn[A]) SetWriteDeadline(t time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.writeDeadline = &t
	return nil
}

func (c *packetConn[A]) getReadContext() (context.Context, context.CancelFunc) {
	ctx := context.Background()
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.readDeadline != nil {
		return context.WithDeadline(ctx, *c.readDeadline)
	}
	return context.WithCancel(ctx)
}

func (c *packetConn[A]) getWriteContext() (context.Context, context.CancelFunc) {
	ctx := context.Background()
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.writeDeadline != nil {
		return context.WithDeadline(ctx, *c.writeDeadline)
	}
	return context.WithCancel(ctx)
}

func (c *packetConn[A]) Close() error {
	return c.swarm.Close()
}

type Addr[A p2p.Addr] struct {
	p2p.Swarm[A]
	Addr A
}

func NewAddr[A p2p.Addr](s p2p.Swarm[A], a A) net.Addr {
	return Addr[A]{s, a}
}

func (a Addr[A]) Network() string {
	return fmt.Sprintf("p2p-%T", a.Swarm)
}

func (a Addr[A]) String() string {
	data, _ := a.Addr.MarshalText()
	return string(data)
}
