package p2pmux

import (
	"context"
	"encoding/binary"
	"sync"

	"github.com/brendoncarroll/go-p2p"
	"github.com/brendoncarroll/go-p2p/s/swarmutil"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
)

// Int
type IntMux interface {
	Open(c uint64) p2p.Swarm
}

type IntAskMux interface {
	Open(c uint64) p2p.AskSwarm
}

type IntSecureMux interface {
	Open(c uint64) p2p.SecureSwarm
}

type IntSecureAskMux interface {
	Open(c uint64) p2p.SecureAskSwarm
}

// Uint32
type Uint32Mux interface {
	Open(c uint32) p2p.Swarm
}

type Uint32AskMux interface {
	Open(c uint32) p2p.AskSwarm
}

type Uint32SecureMux interface {
	Open(c uint32) p2p.SecureSwarm
}

type Uint32SecureAskMux interface {
	Open(c uint32) p2p.SecureAskSwarm
}

// Uint16
type Uint16Mux interface {
	Open(c uint16) p2p.Swarm
}

type Uint16AskMux interface {
	Open(c uint16) p2p.AskSwarm
}

type Uint16SecureMux interface {
	Open(c uint16) p2p.SecureSwarm
}

type Uint16SecureAskMux interface {
	Open(c uint16) p2p.SecureAskSwarm
}

// String
type StringMux interface {
	Open(c string) p2p.Swarm
}

type StringAskMux interface {
	Open(c string) p2p.AskSwarm
}

type StringSecureMux interface {
	Open(c string) p2p.SecureSwarm
}

type StringSecureAskMux interface {
	Open(c string) p2p.SecureAskSwarm
}

var log = p2p.Logger

type channelID interface{}

type muxFunc = func(c channelID, x p2p.IOVec) p2p.IOVec
type demuxFunc = func(data []byte) (channelID, []byte, error)

type muxCore struct {
	swarm     p2p.Swarm
	asker     p2p.Asker
	secure    p2p.Secure
	muxFunc   muxFunc
	demuxFunc demuxFunc

	cf     context.CancelFunc
	swarms sync.Map
}

func newMuxCore(swarm p2p.Swarm, mf muxFunc, dmf demuxFunc) *muxCore {
	ctx, cf := context.WithCancel(context.Background())
	mc := &muxCore{
		swarm:     swarm,
		muxFunc:   mf,
		demuxFunc: dmf,
		cf:        cf,
	}
	if asker, ok := swarm.(p2p.Asker); ok {
		mc.asker = asker
	}
	if secure, ok := swarm.(p2p.Secure); ok {
		mc.secure = secure
	}
	go func() {
		if err := mc.recvLoop(ctx); err != nil && err != p2p.ErrSwarmClosed {
			log.Error(err)
		}
	}()
	if mc.asker != nil {
		go func() {
			if err := mc.serveLoop(ctx); err != nil && err != p2p.ErrSwarmClosed {
				log.Error(err)
			}
		}()
	}
	return mc
}

func (mc *muxCore) recvLoop(ctx context.Context) error {
	buf := make([]byte, mc.swarm.MaxIncomingSize())
	for {
		var src, dst p2p.Addr
		n, err := mc.swarm.Receive(ctx, &src, &dst, buf)
		if err != nil {
			return err
		}
		if err := func() error {
			cid, body, err := mc.demuxFunc(buf[:n])
			if err != nil {
				return errors.Wrapf(err, "error demultiplexing: ")
			}
			s, err := mc.getSwarm(cid)
			if err != nil {
				return err
			}
			return s.tellHub.Deliver(ctx, p2p.Message{
				Src:     src,
				Dst:     dst,
				Payload: body,
			})
		}(); err != nil {
			logrus.Warn(err)
		}
	}
}

func (mc *muxCore) serveLoop(ctx context.Context) error {
	for {
		if err := mc.asker.ServeAsk(ctx, func(ctx context.Context, resp []byte, req p2p.Message) int {
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
				respN, err = ms.askHub.Deliver(ctx, resp, p2p.Message{
					Dst:     req.Dst,
					Src:     req.Src,
					Payload: body,
				})
				return err
			}(); err != nil {
				log.Warn(err)
				return -1
			}
			return respN
		}); err != nil {
			return err
		}
	}
}

func (mc *muxCore) tell(ctx context.Context, cid channelID, dst p2p.Addr, x p2p.IOVec) error {
	y := mc.muxFunc(cid, x)
	return mc.swarm.Tell(ctx, dst, y)
}

func (mc *muxCore) ask(ctx context.Context, cid channelID, resp []byte, dst p2p.Addr, x p2p.IOVec) (int, error) {
	y := mc.muxFunc(cid, x)
	return mc.asker.Ask(ctx, resp, dst, y)
}

func (mc *muxCore) getSwarm(cid channelID) (*muxedSwarm, error) {
	v, ok := mc.swarms.Load(cid)
	if !ok {
		return nil, errors.Errorf("no swarm for channel: %v", v)
	}
	return v.(*muxedSwarm), nil
}

func (mc *muxCore) open(cid channelID) *muxedSwarm {
	newMS := newMuxedSwarm(mc, cid)
	_, exists := mc.swarms.LoadOrStore(cid, newMS)
	if exists {
		panic("swarm for channel already exists")
	}
	return newMS
}

func (mc *muxCore) deleteSwarm(cid interface{}) {
	mc.swarms.Delete(cid)
}

var _ interface {
	p2p.Swarm
	p2p.AskSwarm
} = &muxedSwarm{}

type muxedSwarm struct {
	cid channelID
	m   *muxCore

	tellHub *swarmutil.TellHub
	askHub  *swarmutil.AskHub

	mu       sync.RWMutex
	isClosed bool
}

func newMuxedSwarm(m *muxCore, cid channelID) *muxedSwarm {
	return &muxedSwarm{
		cid:     cid,
		m:       m,
		tellHub: swarmutil.NewTellHub(),
		askHub:  swarmutil.NewAskHub(),
	}
}

func (ms *muxedSwarm) Tell(ctx context.Context, dst p2p.Addr, data p2p.IOVec) error {
	if err := ms.checkClosed(); err != nil {
		return err
	}
	return ms.m.tell(ctx, ms.cid, dst, data)
}

func (ms *muxedSwarm) Receive(ctx context.Context, src, dst *p2p.Addr, buf []byte) (int, error) {
	return ms.tellHub.Receive(ctx, src, dst, buf)
}

func (ms *muxedSwarm) Ask(ctx context.Context, resp []byte, dst p2p.Addr, data p2p.IOVec) (int, error) {
	if err := ms.checkClosed(); err != nil {
		return 0, err
	}
	return ms.m.ask(ctx, ms.cid, resp, dst, data)
}

func (ms *muxedSwarm) ServeAsk(ctx context.Context, fn p2p.AskHandler) error {
	return ms.askHub.ServeAsk(ctx, fn)
}

func (ms *muxedSwarm) LocalAddrs() []p2p.Addr {
	return ms.m.swarm.LocalAddrs()
}

func (ms *muxedSwarm) ParseAddr(data []byte) (p2p.Addr, error) {
	return ms.m.swarm.ParseAddr(data)
}

func (ms *muxedSwarm) MTU(ctx context.Context, addr p2p.Addr) int {
	return ms.m.swarm.MTU(ctx, addr) - binary.MaxVarintLen64
}

func (ms *muxedSwarm) MaxIncomingSize() int {
	return ms.m.swarm.MaxIncomingSize()
}

func (ms *muxedSwarm) Close() error {
	ms.mu.Lock()
	ms.isClosed = true
	ms.mu.Unlock()
	ms.m.deleteSwarm(ms.cid)
	ms.tellHub.CloseWithError(p2p.ErrSwarmClosed)
	ms.askHub.CloseWithError(p2p.ErrSwarmClosed)
	return nil
}

func (ms *muxedSwarm) checkClosed() error {
	ms.mu.RLock()
	defer ms.mu.RUnlock()
	if ms.isClosed {
		return p2p.ErrSwarmClosed
	}
	return nil
}
