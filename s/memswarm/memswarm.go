package memswarm

import (
	"sync/atomic"

	"github.com/brendoncarroll/go-p2p"
	"github.com/brendoncarroll/go-p2p/s/vswarm"
)

type Message = p2p.Message[Addr]

type Realm struct {
	vr vswarm.Realm[Addr]
	n  atomic.Int32
}

func NewRealm(opts ...Option) *Realm {
	return &Realm{
		vr: *vswarm.New[Addr](ParseAddr, opts...),
	}
}

func (r *Realm) NewSwarm() *vswarm.Swarm[Addr] {
	n := r.n.Add(1) - 1
	return r.vr.Create(Addr{N: int(n)})
}

type SecureRealm[Pub any] struct {
	vr vswarm.SecureRealm[Addr, Pub]
	n  atomic.Int32
}

func NewSecureRealm[Pub any](opts ...Option) *SecureRealm[Pub] {
	return &SecureRealm[Pub]{
		vr: *vswarm.NewSecure[Addr, Pub](ParseAddr, opts...),
	}
}

func (sr *SecureRealm[Pub]) NewSwarm(pub Pub) *vswarm.SecureSwarm[Addr, Pub] {
	n := sr.n.Add(1) - 1
	return sr.vr.Create(Addr{N: int(n)}, pub)
}

type Option = vswarm.Option[Addr]

func WithQueueLen(n int) Option {
	return vswarm.WithQueueLen[Addr](n)
}

func WithMTU(n int) Option {
	return vswarm.WithMTU[Addr](n)
}

func WithTellTransform(tf func(*Message) bool) Option {
	return vswarm.WithTellTransform[Addr](tf)
}
