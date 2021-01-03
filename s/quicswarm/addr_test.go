package quicswarm

import (
	"net"
	"testing"

	"github.com/brendoncarroll/go-p2p"
	"github.com/brendoncarroll/go-p2p/p2ptest"
	"github.com/brendoncarroll/go-p2p/s/swarmtest"
)

func TestHasUDP(t *testing.T) {
	swarmtest.TestHasUDP(t, func() p2p.Addr {
		priv := p2ptest.NewTestKey(t, 0)
		id := p2p.NewPeerID(priv.Public())
		return &Addr{
			ID:   id,
			IP:   net.IPv4(100, 0, 0, 1),
			Port: 500,
		}
	})
}
