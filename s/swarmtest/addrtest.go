package swarmtest

import (
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
	"go.brendoncarroll.net/p2p"
)

func TestHasUDP(t *testing.T, newAddr func() p2p.Addr) {
	x := newAddr()
	xudp := p2p.ExtractUDP(x)
	y := p2p.MapUDP(x, func(x net.UDPAddr) net.UDPAddr {
		xip := x.IP.To4()
		return net.UDPAddr{
			IP:   net.IPv4(xip[0], xip[1], xip[2], xip[3]+1),
			Port: x.Port + 1,
		}
	})
	yudp := p2p.ExtractUDP(y)
	assert.Equal(t, xudp.Port+1, yudp.Port)
	assert.Equal(t, xudp.IP.To4()[3]+1, yudp.IP.To4()[3])
}
