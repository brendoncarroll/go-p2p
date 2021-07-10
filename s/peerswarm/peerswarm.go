package peerswarm

import (
	"context"

	"github.com/brendoncarroll/go-p2p"
)

type Swarm interface {
	p2p.SecureSwarm
	TellPeer(ctx context.Context, dst p2p.PeerID, data p2p.IOVec) error
}

type AskSwarm interface {
	p2p.SecureAskSwarm
	AskPeer(ctx context.Context, resp []byte, dst p2p.PeerID, data p2p.IOVec) (int, error)
}
