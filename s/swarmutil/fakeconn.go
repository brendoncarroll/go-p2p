package swarmutil

import (
	"context"
	"io"
	"net"
	"sync"
	"time"

	"github.com/brendoncarroll/go-p2p"
)

var _ net.Conn = &FakeConn{}

type FakeConn struct {
	onWrite      func(context.Context, []byte) error
	laddr, raddr p2p.Addr

	closed   chan struct{}
	incoming chan incomingMsg

	mu            sync.Mutex
	readDeadline  time.Time
	writeDeadline time.Time
}

func NewFakeConn(laddr, raddr p2p.Addr, onWrite func(context.Context, []byte) error) *FakeConn {
	return &FakeConn{
		onWrite:  onWrite,
		laddr:    laddr,
		raddr:    raddr,
		closed:   make(chan struct{}),
		incoming: make(chan incomingMsg),
	}
}

func (c *FakeConn) Deliver(msg []byte) error {
	if isClosedChan(c.closed) {
		return io.ErrClosedPipe
	}
	done := make(chan struct{})
	c.incoming <- incomingMsg{
		data: msg,
		done: done,
	}
	<-done
	return nil
}

func (c *FakeConn) Read(p []byte) (n int, err error) {
	ctx := context.Background()
	c.mu.Lock()
	if !c.readDeadline.IsZero() {
		ctx2, cf := context.WithDeadline(ctx, c.readDeadline)
		ctx = ctx2
		defer cf()
	}
	c.mu.Unlock()
	select {
	case <-ctx.Done():
		return 0, ctx.Err()
	case msg := <-c.incoming:
		if len(p) >= len(msg.data) {
			n = copy(p, msg.data)
		} else {
			err = io.ErrShortBuffer
		}
		close(msg.done)
		return n, err
	}
}

func (c *FakeConn) Write(p []byte) (n int, err error) {
	if isClosedChan(c.closed) {
		return 0, io.ErrClosedPipe
	}
	c.mu.Lock()
	ctx := context.Background()
	if !c.writeDeadline.IsZero() {
		ctx2, cf := context.WithDeadline(ctx, c.writeDeadline)
		ctx = ctx2
		defer cf()
	}
	c.mu.Unlock()

	err = c.onWrite(ctx, p)
	return len(p), err
}

func (c *FakeConn) Close() error {
	if !isClosedChan(c.closed) {
		close(c.closed)
		close(c.incoming)
	}
	return nil
}

func (c *FakeConn) LocalAddr() net.Addr {
	return FakeAddr(c.laddr.Key())
}

func (c *FakeConn) RemoteAddr() net.Addr {
	return FakeAddr(c.raddr.Key())
}

func (c *FakeConn) SetDeadline(t time.Time) error {
	if isClosedChan(c.closed) {
		return io.ErrClosedPipe
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.readDeadline = t
	c.writeDeadline = t
	return nil
}

func (c *FakeConn) SetReadDeadline(t time.Time) error {
	if isClosedChan(c.closed) {
		return io.ErrClosedPipe
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.readDeadline = t
	return nil
}

func (c *FakeConn) SetWriteDeadline(t time.Time) error {
	if isClosedChan(c.closed) {
		return io.ErrClosedPipe
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.writeDeadline = t
	return nil
}

func isClosedChan(x chan struct{}) bool {
	select {
	case <-x:
		return true
	default:
		return false
	}
}

type FakeAddr string

func (a FakeAddr) Network() string {
	return "p2p"
}

func (a FakeAddr) String() string {
	return string(a)
}

type incomingMsg struct {
	data []byte
	done chan struct{}
}
