package mapswarm

import (
	"context"

	"go.brendoncarroll.net/p2p"
)

func New[Above, Below p2p.Addr](x p2p.Swarm[Below], downward func(Above) Below, upward func(Below) Above, parser p2p.AddrParser[Above]) p2p.Swarm[Above] {
	return newSwarm(x, downward, upward, parser)
}

func NewSecure[Above, Below p2p.Addr, Public any](x p2p.SecureSwarm[Below, Public], downward func(Above) Below, upward func(Below) Above, parser p2p.AddrParser[Above]) p2p.SecureSwarm[Above, Public] {
	return p2p.ComposeSecureSwarm[Above, Public](
		newSwarm[Above, Below](x, downward, upward, parser),
		newSecure[Above, Below, Public](x, downward),
	)
}

type swarm[Above, Below p2p.Addr] struct {
	p2p.Swarm[Below]
	downward  func(Above) Below
	upward    func(Below) Above
	parseAddr func([]byte) (Above, error)
}

func newSwarm[Above, Below p2p.Addr](x p2p.Swarm[Below], downward func(Above) Below, upward func(Below) Above, parser p2p.AddrParser[Above]) *swarm[Above, Below] {
	return &swarm[Above, Below]{
		Swarm:     x,
		downward:  downward,
		upward:    upward,
		parseAddr: parser,
	}
}

func (s *swarm[Above, Below]) Tell(ctx context.Context, dst Above, data p2p.IOVec) error {
	return s.Swarm.Tell(ctx, s.downward(dst), data)
}

func (s *swarm[Above, Below]) Receive(ctx context.Context, th func(p2p.Message[Above])) error {
	return s.Swarm.Receive(ctx, func(m p2p.Message[Below]) {
		th(p2p.Message[Above]{
			Src:     s.upward(m.Src),
			Dst:     s.upward(m.Dst),
			Payload: m.Payload,
		})
	})
}

func (s *swarm[Above, Below]) LocalAddrs() []Above {
	xs := s.Swarm.LocalAddrs()
	ys := make([]Above, len(xs))
	for i := range xs {
		ys[i] = s.upward(xs[i])
	}
	return ys
}

func (s *swarm[Above, Below]) MTU() int {
	return s.Swarm.MTU()
}

func (s *swarm[Above, Below]) ParseAddr(data []byte) (Above, error) {
	return s.parseAddr(data)
}

type secure[Above, Below p2p.Addr, Public any] struct {
	p2p.Secure[Below, Public]
	downward func(Above) Below
}

func newSecure[Above, Below p2p.Addr, Public any](x p2p.Secure[Below, Public], downward func(Above) Below) secure[Above, Below, Public] {
	return secure[Above, Below, Public]{
		Secure:   x,
		downward: downward,
	}
}

func (s secure[Above, Below, Public]) LookupPublicKey(ctx context.Context, addr Above) (Public, error) {
	return s.Secure.LookupPublicKey(ctx, s.downward(addr))
}
