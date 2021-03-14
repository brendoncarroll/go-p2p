package p2pconn

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/brendoncarroll/go-p2p"
	"github.com/brendoncarroll/go-p2p/s/swarmutil"
)

// NewPacketConn turns a swarm into a net.PacketConn
// It only uses tells, asks are ignored.
func NewPacketConn(s p2p.Swarm) net.PacketConn {
	pc := &packetConn{
		swarm: s,
		queue: swarmutil.NewTellQueue(),
	}
	go func() {
		err := s.ServeTells(pc.queue.DeliverTell)
		pc.queue.CloseWithError(err)
	}()
	return pc
}

type packetConn struct {
	swarm p2p.Swarm
	queue *swarmutil.TellQueue

	mu                          sync.Mutex
	readDeadline, writeDeadline *time.Time
}

func (c *packetConn) WriteTo(p []byte, to net.Addr) (int, error) {
	target := to.(addr)
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
	if err := c.queue.ServeTell(ctx, func(msg *p2p.Message) {
		from = addr{Swarm: c.swarm, Addr: msg.Src}
		n = copy(p, msg.Payload)
	}); err != nil {
		return 0, nil, err
	}
	return n, from, nil
}

func (c *packetConn) LocalAddr() net.Addr {
	return addr{Addr: c.swarm.LocalAddrs()[0], Swarm: c.swarm}
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

type addr struct {
	p2p.Addr
	p2p.Swarm
}

func (a addr) Network() string {
	return fmt.Sprintf("p2p-%T", a.Swarm)
}

func (a addr) String() string {
	data, _ := a.Addr.MarshalText()
	return string(data)
}
