package swarmutil

import (
	"context"
	"io"
	"net"
	"time"
)

var _ net.Conn = &FakeConn{}

type FakeConn struct {
	OnWrite      func(context.Context, []byte) error
	LAddr, RAddr string

	isClosed    bool
	incoming    chan []byte
	doneReading chan struct{}
}

func NewFakeConn() *FakeConn {
	return &FakeConn{
		incoming:    make(chan []byte),
		doneReading: make(chan struct{}),
	}
}

func (c *FakeConn) Deliver(msg []byte) {
	if c.isClosed {
		return
	}
	c.incoming <- msg
	<-c.doneReading
}

func (c *FakeConn) Read(p []byte) (n int, err error) {
	buf := <-c.incoming

	if len(p) >= len(buf) {
		n = copy(p, buf)
	} else {
		err = io.ErrShortBuffer
	}

	c.doneReading <- struct{}{}
	return n, err
}

func (c *FakeConn) Write(p []byte) (n int, err error) {
	err = c.OnWrite(context.TODO(), p)
	return len(p), err
}

func (c *FakeConn) Close() error {
	c.isClosed = true
	return nil
}

func (c *FakeConn) LocalAddr() net.Addr {
	return FakeAddr(c.LAddr)
}

func (c *FakeConn) RemoteAddr() net.Addr {
	return FakeAddr(c.RAddr)
}

func (c *FakeConn) SetDeadline(deadline time.Time) error {
	panic("not implemented")
}

func (c *FakeConn) SetReadDeadline(t time.Time) error {
	panic("not implemented")
}

func (c *FakeConn) SetWriteDeadline(t time.Time) error {
	panic("not implemented")
}

type FakeAddr string

func (a FakeAddr) Network() string {
	return "p2p"
}

func (a FakeAddr) String() string {
	return string(a)
}
