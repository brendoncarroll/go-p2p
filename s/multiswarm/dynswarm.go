package multiswarm

import (
	"context"

	"github.com/brendoncarroll/go-p2p"
)

type dynSwarm[T p2p.Addr] struct {
	swarm  p2p.Swarm[T]
	asker  p2p.Asker[T]
	secure p2p.Secure[T]
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

func (ds dynSwarm[T]) MTU(ctx context.Context, target p2p.Addr) int {
	return ds.swarm.MTU(ctx, target.(T))
}

func (ds dynSwarm[T]) MaxIncomingSize() int {
	return ds.swarm.MaxIncomingSize()
}

func (ds dynSwarm[T]) ParseAddr(data []byte) (*p2p.Addr, error) {
	addr, err := ds.swarm.ParseAddr(data)
	if err != nil {
		return nil, err
	}
	var ret p2p.Addr = *addr
	return &ret, nil
}

func (ds dynSwarm[T]) Close() error {
	return ds.swarm.Close()
}

func (ds dynSwarm[T]) Ask(ctx context.Context, resp []byte, dst p2p.Addr, req p2p.IOVec) (int, error) {
	return ds.asker.Ask(ctx, resp, dst.(T), req)
}

func (ds dynSwarm[T]) ServeAsk(ctx context.Context, fn func(context.Context, []byte, p2p.Message[p2p.Addr]) int) error {
	return ds.asker.ServeAsk(ctx, func(ctx context.Context, resp []byte, req p2p.Message[T]) int {
		return fn(ctx, resp, p2p.Message[p2p.Addr]{
			Src:     req.Src,
			Dst:     req.Dst,
			Payload: req.Payload,
		})
	})
}

func (ds dynSwarm[T]) PublicKey() p2p.PublicKey {
	return ds.secure.PublicKey()
}

func (ds dynSwarm[T]) LookupPublicKey(ctx context.Context, target p2p.Addr) (p2p.PublicKey, error) {
	return ds.secure.LookupPublicKey(ctx, target.(T))
}
