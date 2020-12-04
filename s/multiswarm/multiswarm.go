package multiswarm

import (
	"context"
	"io"

	"github.com/brendoncarroll/go-p2p"
	"github.com/pkg/errors"
)

var (
	log = p2p.Logger

	ErrTransportNotExist = errors.New("transport does not exist")
)

func NewSwarm(m map[string]p2p.Swarm) p2p.Swarm {
	return multiSwarm(m)
}

func NewSecure(m map[string]p2p.SecureSwarm) p2p.SecureSwarm {
	ms := multiSwarm{}
	msec := multiSecure{}

	for name, s := range m {
		ms[name] = s
		msec[name] = s
	}
	return p2p.ComposeSecureSwarm(ms, msec)
}

func NewSecureAsk(m map[string]p2p.SecureAskSwarm) p2p.SecureAskSwarm {
	ms := multiSwarm{}
	ma := multiAsker{}
	msec := multiSecure{}

	for name, s := range m {
		ms[name] = s
		ma[name] = s
		msec[name] = s
	}

	return p2p.ComposeSecureAskSwarm(ms, ma, msec)
}

type multiSwarm map[string]p2p.Swarm

func (mt multiSwarm) Tell(ctx context.Context, addr p2p.Addr, data []byte) error {
	dst := addr.(Addr)
	t, ok := mt[dst.Transport]
	if !ok {
		return ErrTransportNotExist
	}
	return t.Tell(ctx, dst.Addr, data)
}

func (mt multiSwarm) OnTell(fn p2p.TellHandler) {
	for tname, t := range mt {
		tname := tname
		t.OnTell(func(msg *p2p.Message) {
			msg.Src = Addr{
				Transport: tname,
				Addr:      msg.Src,
			}
			msg.Dst = Addr{
				Transport: tname,
				Addr:      msg.Dst,
			}
			fn(msg)
		})
	}
}

func (mt multiSwarm) MTU(ctx context.Context, addr p2p.Addr) int {
	dst := addr.(Addr)
	t, ok := mt[dst.Transport]
	if !ok {
		return -1
	}
	return t.MTU(ctx, dst.Addr)
}

func (mt multiSwarm) LocalAddrs() []p2p.Addr {
	ret := []p2p.Addr{}
	for tname, t := range mt {
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
	for _, t := range mt {
		if err2 := t.Close(); err2 != nil {
			err = err2
			log.Error(err2)
		}
	}
	return err
}

type multiAsker map[string]p2p.Asker

func (ma multiAsker) Ask(ctx context.Context, addr p2p.Addr, data []byte) ([]byte, error) {
	dst := addr.(Addr)
	t, ok := ma[dst.Transport]
	if !ok {
		return nil, ErrTransportNotExist
	}
	return t.Ask(ctx, dst.Addr, data)
}

func (ma multiAsker) OnAsk(fn p2p.AskHandler) {
	for tname, t := range ma {
		t.OnAsk(func(ctx context.Context, msg *p2p.Message, w io.Writer) {
			msg.Src = Addr{
				Transport: tname,
				Addr:      msg.Src,
			}
			msg.Dst = Addr{
				Transport: tname,
				Addr:      msg.Dst,
			}
			fn(ctx, msg, w)
		})
	}
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
