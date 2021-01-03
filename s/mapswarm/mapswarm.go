package mapswarm

import (
	"context"

	"github.com/brendoncarroll/go-p2p"
)

type AddrMapFunc = func(p2p.Addr) p2p.Addr

func New(x p2p.Swarm, downward, upward AddrMapFunc) p2p.Swarm {
	return newSwarm(x, downward, upward)
}

func NewSecure(x p2p.SecureSwarm, downward, upward AddrMapFunc) p2p.SecureSwarm {
	return p2p.ComposeSecureSwarm(
		newSwarm(x, downward, upward),
		newSecure(x, downward),
	)
}

type swarm struct {
	p2p.Swarm
	downward, upward AddrMapFunc
}

func newSwarm(x p2p.Swarm, downward, upward AddrMapFunc) *swarm {
	return &swarm{
		Swarm:    x,
		downward: downward,
		upward:   upward,
	}
}

func (s *swarm) Tell(ctx context.Context, dst p2p.Addr, data []byte) error {
	return s.Swarm.Tell(ctx, s.downward(dst), data)
}

func (s *swarm) OnTell(fn p2p.TellHandler) {
	s.Swarm.OnTell(func(x *p2p.Message) {
		fn(&p2p.Message{
			Src:     s.upward(x.Src),
			Dst:     s.upward(x.Dst),
			Payload: x.Payload,
		})
	})
}

func (s *swarm) LocalAddrs() []p2p.Addr {
	xs := s.Swarm.LocalAddrs()
	ys := make([]p2p.Addr, len(xs))
	for i := range xs {
		ys[i] = s.upward(xs[i])
	}
	return ys
}

type secure struct {
	p2p.Secure
	downward AddrMapFunc
}

func newSecure(x p2p.Secure, downward AddrMapFunc) secure {
	return secure{
		Secure:   x,
		downward: downward,
	}
}

func (s secure) LookupPublicKey(ctx context.Context, addr p2p.Addr) (p2p.PublicKey, error) {
	return s.LookupPublicKey(ctx, s.downward(addr))
}
