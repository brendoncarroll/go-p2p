package stringmux

import (
	"context"
	"encoding/binary"
	"io"
	"sync"

	"github.com/brendoncarroll/go-p2p"
	"github.com/brendoncarroll/go-p2p/s/swarmutil"
	"github.com/pkg/errors"
	"golang.org/x/sync/errgroup"
)

var log = p2p.Logger

type ChannelID = string

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
	*muxCore
}

func WrapSwarm(x p2p.SecureSwarm) Mux {
	return &mux{
		muxCore: newMuxCore(x),
	}
}

func (m *mux) Open(c ChannelID) p2p.Swarm {
	return m.open(c)
}

type askMux struct {
	*muxCore
}

func WrapAskSwarm(x p2p.AskSwarm) AskMux {
	return &askMux{
		muxCore: newMuxCore(x),
	}
}

func (m *askMux) Open(c ChannelID) p2p.AskSwarm {
	return m.open(c)
}

type secureMux struct {
	*muxCore
}

func WrapSecureSwarm(x p2p.SecureSwarm) SecureMux {
	return &secureMux{
		muxCore: newMuxCore(x),
	}
}

func (m *secureMux) Open(c ChannelID) p2p.SecureSwarm {
	ms := m.open(c)
	return p2p.ComposeSecureSwarm(ms, m.secure)
}

type secureAskMux struct {
	*muxCore
}

func WrapSecureAskSwarm(x p2p.SecureAskSwarm) SecureAskMux {
	return &secureAskMux{
		muxCore: newMuxCore(x),
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

	eg     errgroup.Group
	mu     sync.RWMutex
	swarms map[ChannelID]*muxedSwarm
}

func newMuxCore(x p2p.Swarm) *muxCore {
	mc := &muxCore{
		swarms: make(map[ChannelID]*muxedSwarm),
		eg:     errgroup.Group{},
	}
	mc.swarm = x
	mc.eg.Go(func() error {
		return mc.swarm.ServeTells(mc.handleTell)
	})
	if askSwarm, ok := x.(p2p.AskSwarm); ok {
		mc.askSwarm = askSwarm
		mc.eg.Go(func() error {
			return mc.askSwarm.ServeAsks(mc.handleAsk)
		})
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
		return
	}
	s, err := mc.getSwarm(c)
	if err != nil {
		log.Debug(err)
		return
	}
	s.tellHub.DeliverTell(&p2p.Message{
		Dst:     m.Dst,
		Src:     m.Src,
		Payload: data,
	})
}

func (mc *muxCore) handleAsk(ctx context.Context, m *p2p.Message, w io.Writer) {
	c, data, err := readMessage(m.Payload)
	if err != nil {
		log.Error(err)
		return
	}
	s, err := mc.getSwarm(c)
	if err != nil {
		log.Debug(err)
		return
	}
	s.askHub.DeliverAsk(ctx, &p2p.Message{
		Src:     m.Src,
		Dst:     m.Dst,
		Payload: data,
	}, w)
}

func (mc *muxCore) tell(ctx context.Context, dst p2p.Addr, c ChannelID, data p2p.IOVec) error {
	data2 := makeMessage(c, data)
	return mc.swarm.Tell(ctx, dst, data2)
}

func (mc *muxCore) ask(ctx context.Context, dst p2p.Addr, c ChannelID, data p2p.IOVec) ([]byte, error) {
	data = makeMessage(c, data)
	return mc.askSwarm.Ask(ctx, dst, data)
}

func (mc *muxCore) open(c ChannelID) *muxedSwarm {
	mc.mu.Lock()
	defer mc.mu.Unlock()
	_, exists := mc.swarms[c]
	if exists {
		panic("channel already exists")
	}
	msw := newMuxedSwarm(mc, c)
	mc.swarms[c] = msw
	return msw
}

func (mc *muxCore) close(c ChannelID) error {
	mc.mu.Lock()
	defer mc.mu.Unlock()
	delete(mc.swarms, c)
	return nil
}

func (mc *muxCore) getSwarm(c ChannelID) (*muxedSwarm, error) {
	mc.mu.RLock()
	defer mc.mu.RUnlock()
	s, exists := mc.swarms[c]
	if !exists {
		return nil, errors.Errorf("intmux: got message for non-existing channel %v", c)
	}
	return s, nil
}

var _ interface {
	p2p.Swarm
	p2p.AskSwarm
} = &muxedSwarm{}

type muxedSwarm struct {
	c ChannelID
	m *muxCore

	tellHub *swarmutil.TellHub
	askHub  *swarmutil.AskHub
}

func newMuxedSwarm(m *muxCore, c ChannelID) *muxedSwarm {
	return &muxedSwarm{
		c:       c,
		m:       m,
		tellHub: swarmutil.NewTellHub(),
		askHub:  swarmutil.NewAskHub(),
	}
}

func (ms *muxedSwarm) Tell(ctx context.Context, dst p2p.Addr, data p2p.IOVec) error {
	return ms.m.tell(ctx, dst, ms.c, data)
}

func (ms *muxedSwarm) ServeTells(fn p2p.TellHandler) error {
	return ms.tellHub.ServeTells(fn)
}

func (ms *muxedSwarm) Ask(ctx context.Context, dst p2p.Addr, data p2p.IOVec) ([]byte, error) {
	return ms.m.ask(ctx, dst, ms.c, data)
}

func (ms *muxedSwarm) ServeAsks(fn p2p.AskHandler) error {
	return ms.askHub.ServeAsks(fn)
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
	ms.tellHub.CloseWithError(p2p.ErrSwarmClosed)
	ms.askHub.CloseWithError(p2p.ErrSwarmClosed)
	return ms.m.close(ms.c)
}

func makeMessage(c ChannelID, data p2p.IOVec) p2p.IOVec {
	header := make([]byte, binary.MaxVarintLen64+len(c))
	n := binary.PutUvarint(header, uint64(len(c)))
	header = header[:n]
	header = append(header, []byte(c)...)

	ret := p2p.IOVec{}
	ret = append(ret, header)
	ret = append(ret, data...)
	return ret
}

func readMessage(data []byte) (string, []byte, error) {
	chanLength, n := binary.Uvarint(data)
	if n < 1 {
		return "", nil, errors.Errorf("stringmux: could not read message")
	}
	data = data[n:]
	if len(data) < int(chanLength) {
		return "", nil, errors.Errorf("stringmux: length smaller than message")
	}
	chanBytes := data[:chanLength]
	var msg []byte
	if int(chanLength) < len(data) {
		msg = data[chanLength:]
	}
	return string(chanBytes), msg, nil
}
