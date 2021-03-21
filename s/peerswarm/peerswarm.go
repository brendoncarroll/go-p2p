package peerswarm

import (
	"context"

	"github.com/brendoncarroll/go-p2p"
)

type Swarm interface {
	p2p.SecureSwarm
	TellPeer(ctx context.Context, dst p2p.PeerID, data p2p.IOVec) error
}
