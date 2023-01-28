package vswarm

import "github.com/brendoncarroll/go-p2p"

const (
	DefaultMTU      = 1 << 16
	DefaultQueueLen = 1
)

type realmConfig[A p2p.ComparableAddr] struct {
	mtu           int
	queueLen      int
	tellTransform func(*p2p.Message[A]) bool
}

func defaultRealmConfig[A p2p.ComparableAddr]() realmConfig[A] {
	return realmConfig[A]{
		mtu:           DefaultMTU,
		queueLen:      DefaultQueueLen,
		tellTransform: nil,
	}
}

// Options are passed to New and NewSecure to configure Realms.
type Option[A p2p.ComparableAddr] func(*realmConfig[A])

// WithMTU sets the MTU for all Swarms in the Realm.
func WithMTU[A p2p.ComparableAddr](mtu int) Option[A] {
	if mtu < 1 {
		panic(mtu)
	}
	return func(c *realmConfig[A]) {
		c.mtu = mtu
	}
}

// WithQueueLen sets the maximum length of each Node's queue for recieving messages.
// If l < 1 QueueLen will panic.
func WithQueueLen[A p2p.ComparableAddr](l int) Option[A] {
	if l < 1 {
		panic(l)
	}
	return func(c *realmConfig[A]) {
		c.queueLen = l
	}
}

func WithTellTransform[A p2p.ComparableAddr](fn func(x *p2p.Message[A]) bool) Option[A] {
	return func(c *realmConfig[A]) {
		c.tellTransform = fn
	}
}

type swarmConfig struct{}

type SwarmOption[A p2p.ComparableAddr] func(*swarmConfig)
