package multiswarm

import (
	"context"

	"github.com/brendoncarroll/go-p2p"
	"github.com/brendoncarroll/go-p2p/s/swarmutil"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"golang.org/x/sync/errgroup"
)

var (
	log = p2p.Logger

	ErrTransportNotExist = errors.New("transport does not exist")
)

func NewSwarm(m map[string]p2p.Swarm) p2p.Swarm {
	ms := newSwarm(m)
	go ms.recvLoops(context.Background())
	return ms
}

func NewSecure(m map[string]p2p.SecureSwarm) p2p.SecureSwarm {
	ms := newSwarm(convertSecure(m))
	msec := multiSecure{}
	for name, s := range m {
		msec[name] = s
	}
	go ms.recvLoops(context.Background())
	return p2p.ComposeSecureSwarm(ms, msec)
}

func NewSecureAsk(m map[string]p2p.SecureAskSwarm) p2p.SecureAskSwarm {
	ms := newSwarm(convertSecureAsk(m))
	ma := newAsker(map[string]p2p.Asker{})
	msec := multiSecure{}

	for name, s := range m {
		ma.swarms[name] = s
		msec[name] = s
	}
	ctx := context.Background()
	go ms.recvLoops(ctx)
	go func() {
		if err := ma.serveLoops(ctx); err != nil && err != p2p.ErrSwarmClosed {
			log.Error(err)
		}
	}()
	return p2p.ComposeSecureAskSwarm(ms, ma, msec)
}

type multiSwarm struct {
	addrSchema AddrSchema
	swarms     map[string]p2p.Swarm
	tells      *swarmutil.TellHub
}

func newSwarm(m map[string]p2p.Swarm) multiSwarm {
	s := multiSwarm{
		addrSchema: NewSchemaFromSwarms(m),
		swarms:     m,
		tells:      swarmutil.NewTellHub(),
	}
	return s
}

func (mt multiSwarm) Tell(ctx context.Context, addr p2p.Addr, data p2p.IOVec) error {
	dst := addr.(Addr)
	t, ok := mt.swarms[dst.Transport]
	if !ok {
		return ErrTransportNotExist
	}
	return t.Tell(ctx, dst.Addr, data)
}

func (mt multiSwarm) Receive(ctx context.Context, src, dst *p2p.Addr, buf []byte) (int, error) {
	return mt.tells.Receive(ctx, src, dst, buf)
}

func (mt multiSwarm) recvLoops(ctx context.Context) error {
	eg := errgroup.Group{}
	for tname, t := range mt.swarms {
		tname := tname
		t := t
		eg.Go(func() error {
			buf := make([]byte, t.MaxIncomingSize())
			for {
				var src, dst p2p.Addr
				n, err := t.Receive(ctx, &src, &dst, buf)
				if err != nil {
					return err
				}
				msg := p2p.Message{
					Src:     Addr{Transport: tname, Addr: src},
					Dst:     Addr{Transport: tname, Addr: dst},
					Payload: buf[:n],
				}
				if err := mt.tells.Deliver(ctx, msg); err != nil {
					return err
				}
			}
		})
	}
	return eg.Wait()
}

func (ms multiSwarm) ParseAddr(data []byte) (p2p.Addr, error) {
	return ms.addrSchema.ParseAddr(data)
}

func (mt multiSwarm) MTU(ctx context.Context, addr p2p.Addr) int {
	dst := addr.(Addr)
	t, ok := mt.swarms[dst.Transport]
	if !ok {
		return -1
	}
	return t.MTU(ctx, dst.Addr)
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

func (mt multiSwarm) LocalAddrs() []p2p.Addr {
	ret := []p2p.Addr{}
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
	mt.tells.CloseWithError(p2p.ErrSwarmClosed)
	return err
}

type multiAsker struct {
	swarms map[string]p2p.Asker
	asks   *swarmutil.AskHub
}

func newAsker(m map[string]p2p.Asker) multiAsker {
	ma := multiAsker{
		swarms: m,
		asks:   swarmutil.NewAskHub(),
	}
	return ma
}

func (ma multiAsker) Ask(ctx context.Context, resp []byte, addr p2p.Addr, data p2p.IOVec) (int, error) {
	dst := addr.(Addr)
	t, ok := ma.swarms[dst.Transport]
	if !ok {
		return 0, ErrTransportNotExist
	}
	return t.Ask(ctx, resp, dst.Addr, data)
}

func (ma multiAsker) ServeAsk(ctx context.Context, fn p2p.AskHandler) error {
	return ma.asks.ServeAsk(ctx, fn)
}

func (ma multiAsker) serveLoops(ctx context.Context) error {
	eg := errgroup.Group{}
	for tname, t := range ma.swarms {
		tname := tname
		t := t
		eg.Go(func() error {
			for {
				err := t.ServeAsk(ctx, func(ctx context.Context, reqData []byte, msg p2p.Message) int {
					msg.Src = Addr{
						Transport: tname,
						Addr:      msg.Src,
					}
					msg.Dst = Addr{
						Transport: tname,
						Addr:      msg.Dst,
					}
					n, err := ma.asks.Deliver(ctx, reqData, msg)
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

type multiSecure map[string]p2p.Secure

func (ms multiSecure) PublicKey() p2p.PublicKey {
	for _, s := range ms {
		return s.PublicKey()
	}
	return nil
}

func (ms multiSecure) LookupPublicKey(ctx context.Context, addr p2p.Addr) (p2p.PublicKey, error) {
	a := addr.(Addr)
	t, ok := ms[a.Transport]
	if !ok {
		return nil, errors.Errorf("invalid transport: %s", a.Transport)
	}
	return t.LookupPublicKey(ctx, a.Addr)
}

func convertSecure(x map[string]p2p.SecureSwarm) map[string]p2p.Swarm {
	y := make(map[string]p2p.Swarm)
	for k, v := range x {
		y[k] = v
	}
	return y
}

func convertSecureAsk(x map[string]p2p.SecureAskSwarm) map[string]p2p.Swarm {
	y := make(map[string]p2p.Swarm)
	for k, v := range x {
		y[k] = v
	}
	return y
}
