package quicswarm

import (
	"net"

	"go.brendoncarroll.net/p2p"
)

type connWrapper struct {
	net.PacketConn
}

func (cw connWrapper) WriteTo(data []byte, addr net.Addr) (int, error) {
	n, err := cw.PacketConn.WriteTo(data, addr)
	if p2p.IsErrMTUExceeded(err) {
		return len(data), nil
	}
	return n, err
}
