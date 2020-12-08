package intmux

import (
	"context"
	"encoding/binary"
	"io"
	"sync"

	"github.com/brendoncarroll/go-p2p"
	"github.com/brendoncarroll/go-p2p/s/swarmutil"
	"github.com/pkg/errors"
)

var log = p2p.Logger

type ChannelID = uint64

type Mux interface {
	Open(c ChannelID) p2p.Swarm
}

type AskMux interface {
	Open(c ChannelID) p2p.AskSwarm
}

type SecureMux interface {
	Open(c ChannelID) p2p.SecureSwarm
}

type SecureAskMux interface {
	Open(c ChannelID) p2p.SecureAskSwarm
}

type mux struct {
	muxCore
}

func WrapSwarm(x p2p.SecureSwarm) Mux {
	return &mux{
		muxCore: *newMuxCore(x),
	}
}

func (m *mux) Open(c uint64) p2p.Swarm {
	return m.open(c)
}

type askMux struct {
	muxCore
}

func WrapAskSwarm(x p2p.AskSwarm) AskMux {
	return &askMux{
		muxCore: *newMuxCore(x),
	}
}

func (m *askMux) Open(c uint64) p2p.AskSwarm {
	return m.open(c)
}

type secureMux struct {
	muxCore
}

func WrapSecureSwarm(x p2p.SecureSwarm) SecureMux {
	return &secureMux{
		muxCore: *newMuxCore(x),
	}
}

func (m *secureMux) Open(c uint64) p2p.SecureSwarm {
	ms := m.open(c)
	return p2p.ComposeSecureSwarm(ms, m.secure)
}

type secureAskMux struct {
	muxCore
}

func WrapSecureAskMux(x p2p.SecureSwarm) SecureMux {
	return &secureMux{
		muxCore: *newMuxCore(x),
	}
}

func (m *secureAskMux) Open(c ChannelID) p2p.SecureAskSwarm {
	ms := m.open(c)
	return p2p.ComposeSecureAskSwarm(ms, ms, m.secure)
}

type muxCore struct {
	swarm    p2p.Swarm
	askSwarm p2p.AskSwarm
	secure   p2p.Secure

	mu     sync.RWMutex
	swarms map[uint64]*muxedSwarm
}

func newMuxCore(x p2p.Swarm) *muxCore {
	mc := &muxCore{
		swarms: make(map[uint64]*muxedSwarm),
	}
	mc.swarm = x
	mc.swarm.OnTell(mc.handleTell)
	if askSwarm, ok := x.(p2p.AskSwarm); ok {
		mc.askSwarm = askSwarm
		mc.askSwarm.OnAsk(mc.handleAsk)
	}
	if secure, ok := x.(p2p.Secure); ok {
		mc.secure = secure
	}
	return mc
}

func (mc *muxCore) handleTell(m *p2p.Message) {
	c, data, err := readMessage(m.Payload)
	if err != nil {
		log.Error(err)
	}
	mc.mu.RLock()
	th := swarmutil.AtomicGetTH(&mc.swarms[c].onTell)
	mc.mu.RUnlock()
	th(&p2p.Message{
		Dst:     m.Dst,
		Src:     m.Src,
		Payload: data,
	})
}

func (mc *muxCore) handleAsk(ctx context.Context, m *p2p.Message, w io.Writer) {
	c, data, err := readMessage(m.Payload)
	if err != nil {
		log.Error(err)
	}
	mc.mu.RLock()
	ah := swarmutil.AtomicGetAH(&mc.swarms[c].onAsk)
	mc.mu.RUnlock()
	ah(ctx, &p2p.Message{
		Src:     m.Src,
		Dst:     m.Dst,
		Payload: data,
	}, w)
}

func (mc *muxCore) tell(ctx context.Context, dst p2p.Addr, c uint64, data []byte) error {
	data2 := makeMessage(c, data)
	return mc.swarm.Tell(ctx, dst, data2)
}

func (mc *muxCore) ask(ctx context.Context, dst p2p.Addr, c uint64, data []byte) ([]byte, error) {
	data = makeMessage(c, data)
	return mc.askSwarm.Ask(ctx, dst, data)
}

func (mc *muxCore) open(c uint64) *muxedSwarm {
	mc.mu.Lock()
	defer mc.mu.Unlock()
	_, exists := mc.swarms[c]
	if exists {
		panic("channel already exists")
	}
	msw := &muxedSwarm{
		c: c,
		m: mc,

		onTell: p2p.NoOpTellHandler,
		onAsk:  p2p.NoOpAskHandler,
	}
	mc.swarms[c] = msw
	return msw
}

func (mc *muxCore) close(c uint64) error {
	mc.mu.Lock()
	delete(mc.swarms, c)
	mc.mu.Unlock()
	return nil
}

var _ interface {
	p2p.Swarm
	p2p.AskSwarm
} = &muxedSwarm{}

type muxedSwarm struct {
	c uint64
	m *muxCore

	onTell p2p.TellHandler
	onAsk  p2p.AskHandler
}

func (ms *muxedSwarm) Tell(ctx context.Context, dst p2p.Addr, data []byte) error {
	return ms.m.tell(ctx, dst, ms.c, data)
}

func (ms *muxedSwarm) OnTell(fn p2p.TellHandler) {
	swarmutil.AtomicSetTH(&ms.onTell, fn)
}

func (ms *muxedSwarm) Ask(ctx context.Context, dst p2p.Addr, data []byte) ([]byte, error) {
	return ms.m.ask(ctx, dst, ms.c, data)
}

func (ms *muxedSwarm) OnAsk(fn p2p.AskHandler) {
	swarmutil.AtomicSetAH(&ms.onAsk, fn)
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

func (ms *muxedSwarm) Close() error {
	return ms.m.close(ms.c)
}

func makeMessage(c uint64, data []byte) []byte {
	data2 := make([]byte, binary.MaxVarintLen64)
	n := binary.PutUvarint(data2, c)
	data2 = data2[:n]
	data2 = append(data2, data...)
	return data2
}

func readMessage(data []byte) (uint64, []byte, error) {
	c, n := binary.Uvarint(data)
	if n < 1 {
		return 0, nil, errors.Errorf("intmux: could not read message")
	}
	return c, data[n:], nil
}
