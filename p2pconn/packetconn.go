package p2pconn

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/brendoncarroll/go-p2p"
)

// NewPacketConn turns a swarm into a net.PacketConn
// It only uses tells, asks are ignored.
func NewPacketConn(s p2p.Swarm) net.PacketConn {
	return &packetConn{
		swarm: s,
	}
}

type packetConn struct {
	swarm p2p.Swarm

	mu                          sync.Mutex
	readDeadline, writeDeadline *time.Time
}

func (c *packetConn) WriteTo(p []byte, to net.Addr) (int, error) {
	target := to.(Addr)
	ctx, cf := c.getWriteContext()
	defer cf()
	if err := c.swarm.Tell(ctx, target.Addr, p2p.IOVec{p}); err != nil {
		return 0, err
	}
	return len(p), nil
}

func (c *packetConn) ReadFrom(p []byte) (n int, from net.Addr, err error) {
	ctx, cf := c.getReadContext()
	defer cf()
	var src, dst p2p.Addr
	n, err = c.swarm.Receive(ctx, &src, &dst, p)
	if err != nil {
		return 0, nil, err
	}
	from = Addr{Swarm: c.swarm, Addr: src}
	return n, from, nil
}

func (c *packetConn) LocalAddr() net.Addr {
	return Addr{
		Addr:  c.swarm.LocalAddrs()[0],
		Swarm: c.swarm,
	}
}

func (c *packetConn) SetDeadline(t time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.readDeadline = &t
	c.writeDeadline = &t
	return nil
}

func (c *packetConn) SetReadDeadline(t time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.readDeadline = &t
	return nil
}

func (c *packetConn) SetWriteDeadline(t time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.writeDeadline = &t
	return nil
}

func (c *packetConn) getReadContext() (context.Context, context.CancelFunc) {
	ctx := context.Background()
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.readDeadline != nil {
		return context.WithDeadline(ctx, *c.readDeadline)
	}
	return context.WithCancel(ctx)
}

func (c *packetConn) getWriteContext() (context.Context, context.CancelFunc) {
	ctx := context.Background()
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.writeDeadline != nil {
		return context.WithDeadline(ctx, *c.writeDeadline)
	}
	return context.WithCancel(ctx)
}

func (c *packetConn) Close() error {
	return c.swarm.Close()
}

type Addr struct {
	p2p.Swarm
	p2p.Addr
}

func NewAddr(s p2p.Swarm, a p2p.Addr) net.Addr {
	return Addr{s, a}
}

func (a Addr) Network() string {
	return fmt.Sprintf("p2p-%T-%v", a.Swarm, a.Swarm)
}

func (a Addr) String() string {
	data, _ := a.Addr.MarshalText()
	return string(data)
}
