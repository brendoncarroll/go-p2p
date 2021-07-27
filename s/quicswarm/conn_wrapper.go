package quicswarm

import (
	"net"

	"github.com/brendoncarroll/go-p2p"
)

type connWrapper struct {
	net.PacketConn
}

func (cw connWrapper) WriteTo(data []byte, addr net.Addr) (int, error) {
	n, err := cw.PacketConn.WriteTo(data, addr)
	if err == p2p.ErrMTUExceeded {
		return len(data), nil
	}
	return n, err
}
