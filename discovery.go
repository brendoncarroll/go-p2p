package p2p

import (
	"context"
	"time"
)

type DiscoveryService interface {
	Find(ctx context.Context, token string) ([]Addr, error)
	Publish(ctx context.Context, addrs []Addr, ttl time.Duration) error
	GetToken() string
}
