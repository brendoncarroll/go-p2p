package p2p

import (
	"context"
	"time"
)

type DiscoveryService interface {
	Find(ctx context.Context, id PeerID) ([]string, error)
	Announce(ctx context.Context, id PeerID, addrs []string, ttl time.Duration) error
}
