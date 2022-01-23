package multiswarm

import (
	"context"

	"github.com/brendoncarroll/go-p2p"
	"github.com/brendoncarroll/go-p2p/s/swarmutil"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"golang.org/x/sync/errgroup"
)

var log = p2p.Logger

var (
	ErrTransportNotExist = errors.New("transport does not exist")
)

type (
	DynSwarm p2p.Swarm[p2p.Addr]
	DynSecureSwarm p2p.SecureSwarm[p2p.Addr]
	DynSecureAskSwarm p2p.SecureAskSwarm[p2p.Addr]
)

func WrapSwarm[T p2p.Addr](x p2p.Swarm[T]) DynSwarm {
	return dynSwarm[T]{swarm: x}
}

func WrapSecureSwarm[T p2p.Addr] (x p2p.SecureSwarm[T]) DynSecureSwarm {
	return dynSwarm[T]{swarm: x, secure: x}
}

func WrapSecureAskSwarm[T p2p.Addr] (x p2p.SecureAskSwarm[T]) DynSecureAskSwarm {
	return dynSwarm[T]{swarm: x, secure: x, asker: x}
}

// New creates a swarm with a multiplexed addressed space from
// the elements of m
func New(m map[string]DynSwarm) p2p.Swarm[Addr] {
	ms := newMultiSwarm(m)
	go ms.recvLoops(context.Background())
	return ms
}

func NewSecure(m map[string]DynSecureSwarm) p2p.SecureSwarm[Addr] {
	ms := newMultiSwarm(convertSecure(m))
	msec := multiSecure{}
	for name, s := range m {
		msec[name] = s
	}
	go ms.recvLoops(context.Background())
	return p2p.ComposeSecureSwarm[Addr](ms, msec)
}

func NewSecureAsk(m map[string]DynSecureAskSwarm) p2p.SecureAskSwarm[Addr] {
	ms := newMultiSwarm(convertSecureAsk(m))
	ma := newMultiAsker(map[string]p2p.Asker[p2p.Addr]{})
	msec := multiSecure{}

	for name, s := range m {
		ma.swarms[name] = s
		msec[name] = s
	}
	ctx := context.Background()
	go ms.recvLoops(ctx)
	go func() {
		if err := ma.serveLoops(ctx); err != nil && err != p2p.ErrClosed {
			log.Error(err)
		}
	}()
	return p2p.ComposeSecureAskSwarm[Addr](ms, ma, msec)
}

type multiSwarm struct {
	addrSchema AddrSchema
	swarms     map[string]DynSwarm
	tells      *swarmutil.TellHub[Addr]
}

func newMultiSwarm(m map[string]DynSwarm) multiSwarm {
	s := multiSwarm{
		addrSchema: NewSchemaFromSwarms(m),
		swarms:     m,
		tells:      swarmutil.NewTellHub[Addr](),
	}
	return s
}

func (mt multiSwarm) Tell(ctx context.Context, dst Addr, data p2p.IOVec) error {
	t, ok := mt.swarms[dst.Transport]
	if !ok {
		return ErrTransportNotExist
	}
	return t.Tell(ctx, dst.Addr, data)
}

func (mt multiSwarm) Receive(ctx context.Context, th p2p.TellHandler[Addr]) error {
	return mt.tells.Receive(ctx, th)
}

func (mt multiSwarm) recvLoops(ctx context.Context) error {
	eg := errgroup.Group{}
	for tname, t := range mt.swarms {
		tname := tname
		t := t
		eg.Go(func() error {
			for {
				if err := t.Receive(ctx, func(m p2p.Message[p2p.Addr]) {
					mt.tells.Deliver(ctx, p2p.Message[Addr]{
						Src:     Addr{Transport: tname, Addr: m.Src},
						Dst:     Addr{Transport: tname, Addr: m.Dst},
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

func (ms multiSwarm) ParseAddr(data []byte) (*Addr, error) {
	return ms.addrSchema.ParseAddr(data)
}

func (mt multiSwarm) MTU(ctx context.Context, target Addr) int {
	t, ok := mt.swarms[target.Transport]
	if !ok {
		return -1
	}
	return t.MTU(ctx, target.Addr)
}

func (mt multiSwarm) MaxIncomingSize() int {
	var max int
	for _, t := range mt.swarms {
		x := t.MaxIncomingSize()
		if x > max {
			max = x
		}
	}
	return max
}

func (mt multiSwarm) LocalAddrs() (ret []Addr) {
	for tname, t := range mt.swarms {
		for _, addr := range t.LocalAddrs() {
			a := Addr{
				Transport: tname,
				Addr:      addr,
			}
			ret = append(ret, a)
		}
	}
	return ret
}

func (mt multiSwarm) Close() error {
	var err error
	for _, t := range mt.swarms {
		if err2 := t.Close(); err2 != nil {
			err = err2
			log.Error(err2)
		}
	}
	mt.tells.CloseWithError(p2p.ErrClosed)
	return err
}

type multiAsker struct {
	swarms map[string]p2p.Asker[p2p.Addr]
	asks   *swarmutil.AskHub[Addr]
}

func newMultiAsker(m map[string]p2p.Asker[p2p.Addr]) multiAsker {
	ma := multiAsker{
		swarms: m,
		asks:   swarmutil.NewAskHub[Addr](),
	}
	return ma
}

func (ma multiAsker) Ask(ctx context.Context, resp []byte, dst Addr, data p2p.IOVec) (int, error) {
	t, ok := ma.swarms[dst.Transport]
	if !ok {
		return 0, ErrTransportNotExist
	}
	return t.Ask(ctx, resp, dst.Addr, data)
}

func (ma multiAsker) ServeAsk(ctx context.Context, fn p2p.AskHandler[Addr]) error {
	return ma.asks.ServeAsk(ctx, fn)
}

func (ma multiAsker) serveLoops(ctx context.Context) error {
	eg := errgroup.Group{}
	for tname, t := range ma.swarms {
		tname := tname
		t := t
		eg.Go(func() error {
			for {
				err := t.ServeAsk(ctx, func(ctx context.Context, reqData []byte, msg p2p.Message[p2p.Addr]) int {
					msg2 := p2p.Message[Addr]{
						Src: Addr{
							Transport: tname,
							Addr:      msg.Src,
						},
						Dst: Addr{
							Transport: tname,
							Addr: msg.Dst,
						},
						Payload: msg.Payload,
					}
					n, err := ma.asks.Deliver(ctx, reqData, msg2)
					if err != nil {
						logrus.Error("multiswarm: while handling ask", err)
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

type multiSecure map[string]p2p.Secure[p2p.Addr]

func (ms multiSecure) PublicKey() p2p.PublicKey {
	for _, s := range ms {
		return s.PublicKey()
	}
	return nil
}

func (ms multiSecure) LookupPublicKey(ctx context.Context, a Addr) (p2p.PublicKey, error) {
	t, ok := ms[a.Transport]
	if !ok {
		return nil, errors.Errorf("invalid transport: %s", a.Transport)
	}
	return t.LookupPublicKey(ctx, a.Addr)
}

func convertSecure(x map[string]DynSecureSwarm) map[string]DynSwarm {
	y := make(map[string]DynSwarm)
	for k, v := range x {
		y[k] = v
	}
	return y
}

func convertSecureAsk(x map[string]DynSecureAskSwarm) map[string]DynSwarm {
	y := make(map[string]DynSwarm)
	for k, v := range x {
		y[k] = v
	}
	return y
}
