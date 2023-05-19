package multiswarm

import (
	"context"

	"github.com/brendoncarroll/go-p2p"
)

type dynSwarm[T p2p.Addr] struct {
	swarm p2p.Swarm[T]
}

func (ds dynSwarm[T]) Tell(ctx context.Context, dst p2p.Addr, v p2p.IOVec) error {
	return ds.swarm.Tell(ctx, dst.(T), v)
}

func (ds dynSwarm[T]) Receive(ctx context.Context, fn func(p2p.Message[p2p.Addr])) error {
	return ds.swarm.Receive(ctx, func(x p2p.Message[T]) {
		fn(p2p.Message[p2p.Addr]{
			Src:     x.Src,
			Dst:     x.Dst,
			Payload: x.Payload,
		})
	})
}

func (ds dynSwarm[T]) LocalAddrs() (ret []p2p.Addr) {
	for _, addr := range ds.swarm.LocalAddrs() {
		ret = append(ret, addr)
	}
	return ret
}

func (ds dynSwarm[T]) MTU() int {
	return ds.swarm.MTU()
}

func (ds dynSwarm[T]) ParseAddr(data []byte) (p2p.Addr, error) {
	return ds.swarm.ParseAddr(data)
}

func (ds dynSwarm[T]) Close() error {
	return ds.swarm.Close()
}

type dynAsker[T p2p.Addr] struct {
	asker interface {
		p2p.Asker[T]
		p2p.AskServer[T]
	}
}

func (da dynAsker[T]) Ask(ctx context.Context, resp []byte, dst p2p.Addr, req p2p.IOVec) (int, error) {
	return da.asker.Ask(ctx, resp, dst.(T), req)
}

func (da dynAsker[T]) ServeAsk(ctx context.Context, fn func(context.Context, []byte, p2p.Message[p2p.Addr]) int) error {
	return da.asker.ServeAsk(ctx, func(ctx context.Context, resp []byte, req p2p.Message[T]) int {
		return fn(ctx, resp, p2p.Message[p2p.Addr]{
			Src:     req.Src,
			Dst:     req.Dst,
			Payload: req.Payload,
		})
	})
}

type dynSecure[T p2p.Addr, Pub any] struct {
	secure p2p.Secure[T, Pub]
}

func (ds dynSecure[T, Pub]) PublicKey() Pub {
	return ds.secure.PublicKey()
}

func (ds dynSecure[T, Pub]) LookupPublicKey(ctx context.Context, target p2p.Addr) (Pub, error) {
	return ds.secure.LookupPublicKey(ctx, target.(T))
}
