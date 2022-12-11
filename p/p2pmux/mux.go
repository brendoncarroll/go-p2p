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

type Mux[A p2p.Addr, C any] interface {
	Open(c C) p2p.Swarm[A]
}

type AskMux[A p2p.Addr, C any] interface {
	Open(c C) p2p.AskSwarm[A]
}

type SecureMux[A p2p.Addr, C any] interface {
	Open(c C) p2p.SecureSwarm[A]
}

type SecureAskMux[A p2p.Addr, C any] interface {
	Open(c C) p2p.SecureAskSwarm[A]
}

type muxFunc[C any] func(c C, x p2p.IOVec) p2p.IOVec
type demuxFunc[C any] func(data []byte) (C, []byte, error)

type muxCore[A p2p.Addr, C any] struct {
	swarm     p2p.Swarm[A]
	asker     p2p.Asker[A]
	secure    p2p.Secure[A]
	muxFunc   muxFunc[C]
	demuxFunc demuxFunc[C]

	cf     context.CancelFunc
	swarms sync.Map
}

func newMuxCore[A p2p.Addr, C any](bgCtx context.Context, swarm p2p.Swarm[A], mf muxFunc[C], dmf demuxFunc[C]) *muxCore[A, C] {
	ctx, cf := context.WithCancel(bgCtx)
	mc := &muxCore[A, C]{
		swarm:     swarm,
		muxFunc:   mf,
		demuxFunc: dmf,
		cf:        cf,
	}
	if asker, ok := swarm.(p2p.Asker[A]); ok {
		mc.asker = asker
	}
	if secure, ok := swarm.(p2p.Secure[A]); ok {
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

func (mc *muxCore[A, C]) recvLoop(ctx context.Context) error {
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

func (mc *muxCore[A, C]) handleRecv(ctx context.Context, m p2p.Message[A]) error {
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

func (mc *muxCore[A, C]) serveLoop(ctx context.Context) error {
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

func (mc *muxCore[A, C]) tell(ctx context.Context, cid C, dst A, x p2p.IOVec) error {
	y := mc.muxFunc(cid, x)
	return mc.swarm.Tell(ctx, dst, y)
}

func (mc *muxCore[A, C]) ask(ctx context.Context, cid C, resp []byte, dst A, x p2p.IOVec) (int, error) {
	y := mc.muxFunc(cid, x)
	return mc.asker.Ask(ctx, resp, dst, y)
}

func (mc *muxCore[A, C]) lookupPublicKey(ctx context.Context, target A) (p2p.PublicKey, error) {
	return mc.secure.LookupPublicKey(ctx, target)
}

func (mc *muxCore[A, C]) publicKey() p2p.PublicKey {
	return mc.secure.PublicKey()
}

func (mc *muxCore[A, C]) getSwarm(cid C) (*muxedSwarm[A, C], error) {
	v, ok := mc.swarms.Load(cid)
	if !ok {
		return nil, errors.Errorf("p2pmux: no swarm for channel: %v", v)
	}
	return v.(*muxedSwarm[A, C]), nil
}

func (mc *muxCore[A, C]) open(cid C) *muxedSwarm[A, C] {
	newMS := newMuxedSwarm[A, C](mc, cid)
	_, exists := mc.swarms.LoadOrStore(cid, newMS)
	if exists {
		panic("p2pmux: swarm for channel already exists")
	}
	return newMS
}

func (mc *muxCore[A, C]) deleteSwarm(cid C) {
	mc.swarms.Delete(cid)
}

type muxedSwarm[A p2p.Addr, C any] struct {
	cid C
	m   *muxCore[A, C]

	tellHub *swarmutil.TellHub[A]
	askHub  *swarmutil.AskHub[A]

	mu       sync.RWMutex
	isClosed bool
}

func newMuxedSwarm[A p2p.Addr, C any](m *muxCore[A, C], cid C) *muxedSwarm[A, C] {
	return &muxedSwarm[A, C]{
		cid:     cid,
		m:       m,
		tellHub: swarmutil.NewTellHub[A](),
		askHub:  swarmutil.NewAskHub[A](),
	}
}

func (ms *muxedSwarm[A, C]) Tell(ctx context.Context, dst A, data p2p.IOVec) error {
	if err := ms.checkClosed(); err != nil {
		return err
	}
	return ms.m.tell(ctx, ms.cid, dst, data)
}

func (ms *muxedSwarm[A, C]) Receive(ctx context.Context, th func(p2p.Message[A])) error {
	return ms.tellHub.Receive(ctx, th)
}

func (ms *muxedSwarm[A, C]) Ask(ctx context.Context, resp []byte, dst A, data p2p.IOVec) (int, error) {
	if err := ms.checkClosed(); err != nil {
		return 0, err
	}
	return ms.m.ask(ctx, ms.cid, resp, dst, data)
}

func (ms *muxedSwarm[A, C]) ServeAsk(ctx context.Context, fn func(context.Context, []byte, p2p.Message[A]) int) error {
	return ms.askHub.ServeAsk(ctx, fn)
}

func (ms *muxedSwarm[A, C]) LocalAddrs() []A {
	return ms.m.swarm.LocalAddrs()
}

func (ms *muxedSwarm[A, C]) ParseAddr(data []byte) (A, error) {
	return ms.m.swarm.ParseAddr(data)
}

func (ms *muxedSwarm[A, C]) MTU(ctx context.Context, addr A) int {
	return ms.m.swarm.MTU(ctx, addr) - binary.MaxVarintLen64
}

func (ms *muxedSwarm[A, C]) MaxIncomingSize() int {
	return ms.m.swarm.MaxIncomingSize()
}

func (ms *muxedSwarm[A, C]) LookupPublicKey(ctx context.Context, target A) (p2p.PublicKey, error) {
	return ms.m.lookupPublicKey(ctx, target)
}

func (ms *muxedSwarm[A, C]) PublicKey() p2p.PublicKey {
	return ms.m.publicKey()
}

func (ms *muxedSwarm[A, C]) Close() error {
	ms.mu.Lock()
	ms.isClosed = true
	ms.mu.Unlock()
	ms.m.deleteSwarm(ms.cid)
	ms.tellHub.CloseWithError(p2p.ErrClosed)
	ms.askHub.CloseWithError(p2p.ErrClosed)
	return nil
}

func (ms *muxedSwarm[A, C]) checkClosed() error {
	ms.mu.RLock()
	defer ms.mu.RUnlock()
	if ms.isClosed {
		return p2p.ErrClosed
	}
	return nil
}

type mux[A p2p.Addr, C any] struct {
	*muxCore[A, C]
}

func (m mux[A, C]) Open(c C) p2p.Swarm[A] {
	return m.muxCore.open(c)
}

type askMux[A p2p.Addr, C any] struct {
	*muxCore[A, C]
}

func (m askMux[A, C]) Open(c C) p2p.AskSwarm[A] {
	return m.muxCore.open(c)
}

type secureMux[A p2p.Addr, C any] struct {
	*muxCore[A, C]
}

func (m secureMux[A, C]) Open(c C) p2p.SecureSwarm[A] {
	return m.muxCore.open(c)
}

type secureAskMux[A p2p.Addr, C any] struct {
	*muxCore[A, C]
}

func (m secureAskMux[A, C]) Open(c C) p2p.SecureAskSwarm[A] {
	return m.muxCore.open(c)
}
