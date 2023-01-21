package p2pmux

import (
	"context"
	"encoding/binary"
	"sync"

	"github.com/brendoncarroll/go-p2p"
	"github.com/brendoncarroll/go-p2p/s/swarmutil"
	"github.com/brendoncarroll/stdctx/logctx"
	"github.com/pkg/errors"
)

var ctx = context.Background()

type Mux[A p2p.Addr, C comparable] interface {
	Open(c C) p2p.Swarm[A]
}

type AskMux[A p2p.Addr, C comparable] interface {
	Open(c C) p2p.AskSwarm[A]
}

type SecureMux[A p2p.Addr, C comparable, Pub any] interface {
	Open(c C) p2p.SecureSwarm[A, Pub]
}

type SecureAskMux[A p2p.Addr, C comparable, Pub any] interface {
	Open(c C) p2p.SecureAskSwarm[A, Pub]
}

type askBidi[A p2p.Addr] interface {
	p2p.Asker[A]
	p2p.AskServer[A]
}

type muxFunc[C comparable] func(c C, x p2p.IOVec) p2p.IOVec
type demuxFunc[C comparable] func(data []byte) (C, []byte, error)

type muxCore[A p2p.Addr, C comparable, Pub any] struct {
	swarm     p2p.Swarm[A]
	asker     askBidi[A]
	secure    p2p.Secure[A, Pub]
	muxFunc   muxFunc[C]
	demuxFunc demuxFunc[C]

	cf     context.CancelFunc
	swarms sync.Map
}

func newMuxCore[A p2p.Addr, C comparable, Pub any](bgCtx context.Context, swarm p2p.Swarm[A], mf muxFunc[C], dmf demuxFunc[C]) *muxCore[A, C, Pub] {
	ctx, cf := context.WithCancel(bgCtx)
	mc := &muxCore[A, C, Pub]{
		swarm:     swarm,
		muxFunc:   mf,
		demuxFunc: dmf,
		cf:        cf,
	}
	if asker, ok := swarm.(askBidi[A]); ok {
		mc.asker = asker
	}
	if secure, ok := swarm.(p2p.Secure[A, Pub]); ok {
		mc.secure = secure
	}
	go func() {
		if err := mc.recvLoop(ctx); err != nil && !p2p.IsErrClosed(err) {
			logctx.Errorln(ctx, err)
		}
	}()
	if mc.asker != nil {
		go func() {
			if err := mc.serveLoop(ctx); err != nil && !p2p.IsErrClosed(err) {
				logctx.Errorln(ctx, err)
			}
		}()
	}
	return mc
}

func (mc *muxCore[A, C, Pub]) recvLoop(ctx context.Context) error {
	for {
		if err := mc.swarm.Receive(ctx, func(m p2p.Message[A]) {
			if err := mc.handleRecv(ctx, m); err != nil {
				logctx.Warnln(ctx, err)
			}
		}); err != nil {
			return err
		}
	}
}

func (mc *muxCore[A, C, Pub]) handleRecv(ctx context.Context, m p2p.Message[A]) error {
	cid, body, err := mc.demuxFunc(m.Payload)
	if err != nil {
		return errors.Wrapf(err, "error demultiplexing: ")
	}
	s, err := mc.getSwarm(cid)
	if err != nil {
		return err
	}
	return s.tellHub.Deliver(ctx, p2p.Message[A]{
		Src:     m.Src,
		Dst:     m.Dst,
		Payload: body,
	})
}

func (mc *muxCore[A, C, Pub]) serveLoop(ctx context.Context) error {
	for {
		if err := mc.asker.ServeAsk(ctx, func(ctx context.Context, resp []byte, req p2p.Message[A]) int {
			var respN int
			if err := func() error {
				cid, body, err := mc.demuxFunc(req.Payload)
				if err != nil {
					errors.Wrapf(err, "error demultiplexing")
				}
				ms, err := mc.getSwarm(cid)
				if err != nil {
					return err
				}
				respN, err = ms.askHub.Deliver(ctx, resp, p2p.Message[A]{
					Dst:     req.Dst,
					Src:     req.Src,
					Payload: body,
				})
				return err
			}(); err != nil {
				logctx.Warnln(ctx, err)
				return -1
			}
			return respN
		}); err != nil {
			return err
		}
	}
}

func (mc *muxCore[A, C, Pub]) tell(ctx context.Context, cid C, dst A, x p2p.IOVec) error {
	y := mc.muxFunc(cid, x)
	return mc.swarm.Tell(ctx, dst, y)
}

func (mc *muxCore[A, C, Pub]) ask(ctx context.Context, cid C, resp []byte, dst A, x p2p.IOVec) (int, error) {
	y := mc.muxFunc(cid, x)
	return mc.asker.Ask(ctx, resp, dst, y)
}

func (mc *muxCore[A, C, Pub]) lookupPublicKey(ctx context.Context, target A) (Pub, error) {
	return mc.secure.LookupPublicKey(ctx, target)
}

func (mc *muxCore[A, C, Pub]) publicKey() Pub {
	return mc.secure.PublicKey()
}

func (mc *muxCore[A, C, Pub]) getSwarm(cid C) (*muxedSwarm[A, C, Pub], error) {
	v, ok := mc.swarms.Load(cid)
	if !ok {
		return nil, errors.Errorf("p2pmux: no swarm for channel: %v", v)
	}
	return v.(*muxedSwarm[A, C, Pub]), nil
}

func (mc *muxCore[A, C, Pub]) open(cid C) *muxedSwarm[A, C, Pub] {
	newMS := newMuxedSwarm[A, C](mc, cid)
	_, exists := mc.swarms.LoadOrStore(cid, newMS)
	if exists {
		panic("p2pmux: swarm for channel already exists")
	}
	return newMS
}

func (mc *muxCore[A, C, Pub]) deleteSwarm(cid C) {
	mc.swarms.Delete(cid)
}

type muxedSwarm[A p2p.Addr, C comparable, Pub any] struct {
	cid C
	m   *muxCore[A, C, Pub]

	tellHub swarmutil.TellHub[A]
	askHub  swarmutil.AskHub[A]

	mu       sync.RWMutex
	isClosed bool
}

func newMuxedSwarm[A p2p.Addr, C comparable, Pub any](m *muxCore[A, C, Pub], cid C) *muxedSwarm[A, C, Pub] {
	return &muxedSwarm[A, C, Pub]{
		cid:     cid,
		m:       m,
		tellHub: swarmutil.NewTellHub[A](),
		askHub:  swarmutil.NewAskHub[A](),
	}
}

func (ms *muxedSwarm[A, C, Pub]) Tell(ctx context.Context, dst A, data p2p.IOVec) error {
	if err := ms.checkClosed(); err != nil {
		return err
	}
	return ms.m.tell(ctx, ms.cid, dst, data)
}

func (ms *muxedSwarm[A, C, Pub]) Receive(ctx context.Context, th func(p2p.Message[A])) error {
	return ms.tellHub.Receive(ctx, th)
}

func (ms *muxedSwarm[A, C, Pub]) Ask(ctx context.Context, resp []byte, dst A, data p2p.IOVec) (int, error) {
	if err := ms.checkClosed(); err != nil {
		return 0, err
	}
	return ms.m.ask(ctx, ms.cid, resp, dst, data)
}

func (ms *muxedSwarm[A, C, Pub]) ServeAsk(ctx context.Context, fn func(context.Context, []byte, p2p.Message[A]) int) error {
	return ms.askHub.ServeAsk(ctx, fn)
}

func (ms *muxedSwarm[A, C, Pub]) LocalAddrs() []A {
	return ms.m.swarm.LocalAddrs()
}

func (ms *muxedSwarm[A, C, Pub]) ParseAddr(data []byte) (A, error) {
	return ms.m.swarm.ParseAddr(data)
}

func (ms *muxedSwarm[A, C, Pub]) MTU(ctx context.Context, addr A) int {
	return ms.m.swarm.MTU(ctx, addr) - binary.MaxVarintLen64
}

func (ms *muxedSwarm[A, C, Pub]) MaxIncomingSize() int {
	return ms.m.swarm.MaxIncomingSize()
}

func (ms *muxedSwarm[A, C, Pub]) LookupPublicKey(ctx context.Context, target A) (Pub, error) {
	return ms.m.lookupPublicKey(ctx, target)
}

func (ms *muxedSwarm[A, C, Pub]) PublicKey() Pub {
	return ms.m.publicKey()
}

func (ms *muxedSwarm[A, C, Pub]) Close() error {
	ms.mu.Lock()
	ms.isClosed = true
	ms.mu.Unlock()
	ms.m.deleteSwarm(ms.cid)
	ms.tellHub.CloseWithError(p2p.ErrClosed)
	ms.askHub.CloseWithError(p2p.ErrClosed)
	return nil
}

func (ms *muxedSwarm[A, C, Pub]) checkClosed() error {
	ms.mu.RLock()
	defer ms.mu.RUnlock()
	if ms.isClosed {
		return p2p.ErrClosed
	}
	return nil
}

type mux[A p2p.Addr, C comparable] struct {
	*muxCore[A, C, struct{}]
}

func (m mux[A, C]) Open(c C) p2p.Swarm[A] {
	return m.muxCore.open(c)
}

type askMux[A p2p.Addr, C comparable] struct {
	*muxCore[A, C, struct{}]
}

func (m askMux[A, C]) Open(c C) p2p.AskSwarm[A] {
	return m.muxCore.open(c)
}

type secureMux[A p2p.Addr, C comparable, Pub any] struct {
	*muxCore[A, C, Pub]
}

func (m secureMux[A, C, Pub]) Open(c C) p2p.SecureSwarm[A, Pub] {
	return m.muxCore.open(c)
}

type secureAskMux[A p2p.Addr, C comparable, Pub any] struct {
	*muxCore[A, C, Pub]
}

func (m secureAskMux[A, C, Pub]) Open(c C) p2p.SecureAskSwarm[A, Pub] {
	return m.muxCore.open(c)
}
