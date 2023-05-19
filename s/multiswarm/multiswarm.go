package multiswarm

import (
	"context"
	"math"

	"github.com/brendoncarroll/go-p2p"
	"github.com/brendoncarroll/go-p2p/s/swarmutil"
	"github.com/brendoncarroll/stdctx/logctx"
	"github.com/pkg/errors"
	"golang.org/x/sync/errgroup"
)

var (
	ErrTransportNotExist = errors.New("transport does not exist for scheme")
)

type (
	DynSwarm                   p2p.Swarm[p2p.Addr]
	DynSecureSwarm[Pub any]    p2p.SecureSwarm[p2p.Addr, Pub]
	DynSecureAskSwarm[Pub any] p2p.SecureAskSwarm[p2p.Addr, Pub]
)

func WrapSwarm[T p2p.Addr](x p2p.Swarm[T]) DynSwarm {
	return dynSwarm[T]{swarm: x}
}

func WrapSecureSwarm[T p2p.Addr, Pub any](x p2p.SecureSwarm[T, Pub]) DynSecureSwarm[Pub] {
	return p2p.ComposeSecureSwarm[p2p.Addr, Pub](
		dynSwarm[T]{swarm: x},
		dynSecure[T, Pub]{secure: x},
	)
}

func WrapSecureAskSwarm[T p2p.Addr, Pub any](x p2p.SecureAskSwarm[T, Pub]) DynSecureAskSwarm[Pub] {
	return p2p.ComposeSecureAskSwarm[p2p.Addr, Pub](
		dynSwarm[T]{swarm: x},
		dynAsker[T]{asker: x},
		dynSecure[T, Pub]{secure: x},
	)
}

// New creates a swarm with a multiplexed addressed space from
// the elements of m
func New(m map[string]DynSwarm) p2p.Swarm[Addr] {
	ms := newMultiSwarm(m)
	go ms.recvLoops(context.Background())
	return ms
}

func NewSecure[Pub any](m map[string]DynSecureSwarm[Pub]) p2p.SecureSwarm[Addr, Pub] {
	ms := newMultiSwarm(convertSecure(m))
	msec := multiSecure[Pub]{}
	for name, s := range m {
		msec[name] = s
	}
	go ms.recvLoops(context.Background())
	return p2p.ComposeSecureSwarm[Addr, Pub](ms, msec)
}

func NewSecureAsk[Pub any](m map[string]DynSecureAskSwarm[Pub]) p2p.SecureAskSwarm[Addr, Pub] {
	ms := newMultiSwarm(convertSecureAsk(m))
	ma := newMultiAsker(map[string]p2p.AskSwarm[p2p.Addr]{})
	msec := multiSecure[Pub]{}

	for name, s := range m {
		ma.swarms[name] = s
		msec[name] = s
	}
	ctx := context.Background()
	go func() {
		if err := ms.recvLoops(ctx); err != nil && !errors.Is(err, p2p.ErrClosed) {
			logctx.Errorln(ctx, err)
		}
	}()
	go func() {
		if err := ma.serveLoops(ctx); err != nil && !errors.Is(err, p2p.ErrClosed) {
			logctx.Errorln(ctx, err)
		}
	}()
	return p2p.ComposeSecureAskSwarm[Addr, Pub](ms, ma, msec)
}

type multiSwarm struct {
	ctx        context.Context
	addrSchema AddrSchema
	swarms     map[string]DynSwarm
	tells      swarmutil.TellHub[Addr]
}

func newMultiSwarm(m map[string]DynSwarm) *multiSwarm {
	s := &multiSwarm{
		ctx:        context.Background(),
		addrSchema: NewSchemaFromSwarms(m),
		swarms:     m,
		tells:      swarmutil.NewTellHub[Addr](),
	}
	return s
}

func (mt *multiSwarm) Tell(ctx context.Context, dst Addr, data p2p.IOVec) error {
	t, ok := mt.swarms[dst.Scheme]
	if !ok {
		return ErrTransportNotExist
	}
	return t.Tell(ctx, dst.Addr, data)
}

func (mt *multiSwarm) Receive(ctx context.Context, th func(p2p.Message[Addr])) error {
	return mt.tells.Receive(ctx, th)
}

func (mt *multiSwarm) recvLoops(ctx context.Context) error {
	eg := errgroup.Group{}
	for tname, t := range mt.swarms {
		tname := tname
		t := t
		eg.Go(func() error {
			for {
				if err := t.Receive(ctx, func(m p2p.Message[p2p.Addr]) {
					mt.tells.Deliver(ctx, p2p.Message[Addr]{
						Src:     Addr{Scheme: tname, Addr: m.Src},
						Dst:     Addr{Scheme: tname, Addr: m.Dst},
						Payload: m.Payload,
					})
				}); err != nil {
					return err
				}
			}
		})
	}
	return eg.Wait()
}

func (ms *multiSwarm) ParseAddr(data []byte) (Addr, error) {
	return ms.addrSchema.ParseAddr(data)
}

func (mt *multiSwarm) MTU() int {
	ret := math.MaxInt
	for _, s := range mt.swarms {
		if m := s.MTU(); m < ret {
			ret = m
		}
	}
	return ret
}

func (mt *multiSwarm) LocalAddrs() (ret []Addr) {
	for tname, t := range mt.swarms {
		for _, addr := range t.LocalAddrs() {
			a := Addr{
				Scheme: tname,
				Addr:   addr,
			}
			ret = append(ret, a)
		}
	}
	return ret
}

func (mt *multiSwarm) Close() error {
	var err error
	for _, t := range mt.swarms {
		if err2 := t.Close(); err2 != nil {
			err = err2
			logctx.Errorln(mt.ctx, "closing swarms", err)
		}
	}
	mt.tells.CloseWithError(p2p.ErrClosed)
	return err
}

type multiAsker struct {
	swarms map[string]p2p.AskSwarm[p2p.Addr]
	asks   swarmutil.AskHub[Addr]
}

func newMultiAsker(m map[string]p2p.AskSwarm[p2p.Addr]) *multiAsker {
	ma := &multiAsker{
		swarms: m,
		asks:   swarmutil.NewAskHub[Addr](),
	}
	return ma
}

func (ma *multiAsker) Ask(ctx context.Context, resp []byte, dst Addr, data p2p.IOVec) (int, error) {
	t, ok := ma.swarms[dst.Scheme]
	if !ok {
		return 0, ErrTransportNotExist
	}
	return t.Ask(ctx, resp, dst.Addr, data)
}

func (ma *multiAsker) ServeAsk(ctx context.Context, fn func(context.Context, []byte, p2p.Message[Addr]) int) error {
	return ma.asks.ServeAsk(ctx, fn)
}

func (ma *multiAsker) serveLoops(ctx context.Context) error {
	eg := errgroup.Group{}
	for scheme, t := range ma.swarms {
		scheme := scheme
		t := t
		eg.Go(func() error {
			for {
				err := t.ServeAsk(ctx, func(ctx context.Context, reqData []byte, msg p2p.Message[p2p.Addr]) int {
					msg2 := p2p.Message[Addr]{
						Src: Addr{
							Scheme: scheme,
							Addr:   msg.Src,
						},
						Dst: Addr{
							Scheme: scheme,
							Addr:   msg.Dst,
						},
						Payload: msg.Payload,
					}
					n, err := ma.asks.Deliver(ctx, reqData, msg2)
					if err != nil {
						logctx.Errorln(ctx, "multiswarm: while handling ask", err)
						return -1
					}
					return n
				})
				if err != nil {
					return err
				}
			}
		})
	}
	return eg.Wait()
}

type multiSecure[Pub any] map[string]p2p.Secure[p2p.Addr, Pub]

func (ms multiSecure[Pub]) PublicKey() (ret Pub) {
	for _, s := range ms {
		return s.PublicKey()
	}
	return ret
}

func (ms multiSecure[Pub]) LookupPublicKey(ctx context.Context, a Addr) (Pub, error) {
	t, ok := ms[a.Scheme]
	if !ok {
		var zero Pub
		return zero, errors.Errorf("invalid transport: %s", a.Scheme)
	}
	return t.LookupPublicKey(ctx, a.Addr)
}

func convertSecure[Pub any](x map[string]DynSecureSwarm[Pub]) map[string]DynSwarm {
	y := make(map[string]DynSwarm)
	for k, v := range x {
		y[k] = v
	}
	return y
}

func convertSecureAsk[Pub any](x map[string]DynSecureAskSwarm[Pub]) map[string]DynSwarm {
	y := make(map[string]DynSwarm)
	for k, v := range x {
		y[k] = v
	}
	return y
}
