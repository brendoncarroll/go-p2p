package intmux

import (
	"context"
	"encoding/binary"
	"sync"

	"github.com/brendoncarroll/go-p2p"
	"github.com/brendoncarroll/go-p2p/s/swarmutil"
	"github.com/pkg/errors"
	"golang.org/x/sync/errgroup"
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

func WrapSecureAskMux(x p2p.SecureSwarm) SecureMux {
	return &secureMux{
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
	ctx := context.Background()
	mc.eg.Go(func() error {
		return mc.recvLoop(ctx)
	})
	if askSwarm, ok := x.(p2p.AskSwarm); ok {
		mc.askSwarm = askSwarm
		mc.eg.Go(func() error {
			return mc.serveLoop(ctx)
		})
	}
	if secure, ok := x.(p2p.Secure); ok {
		mc.secure = secure
	}
	return mc
}

func (mc *muxCore) recvLoop(ctx context.Context) error {
	buf := make([]byte, mc.swarm.MaxIncomingSize())
	for {
		var src, dst p2p.Addr
		n, err := mc.swarm.Recv(ctx, &src, &dst, buf)
		if err != nil {
			return err
		}
		c, data, err := readMessage(buf[:n])
		if err != nil {
			log.Error(err)
			continue
		}
		s, err := mc.getSwarm(c)
		if err != nil {
			log.Debug(err)
			continue
		}
		if err := s.tellHub.Deliver(ctx, p2p.Message{
			Dst:     dst,
			Src:     src,
			Payload: data,
		}); err != nil {
			return err
		}
	}
}

func (mc *muxCore) serveLoop(ctx context.Context) error {
	for {
		err := mc.askSwarm.ServeAsk(ctx, func(resp []byte, req p2p.Message) int {
			c, data, err := readMessage(req.Payload)
			if err != nil {
				log.Error(err)
				return 0
			}
			s, err := mc.getSwarm(c)
			if err != nil {
				log.Debug(err)
				return 0
			}
			n, err := s.askHub.Deliver(ctx, resp, p2p.Message{
				Src:     req.Src,
				Dst:     req.Dst,
				Payload: data,
			})
			if err != nil {
				return 0
			}
			return n
		})
		if err != nil {
			return err
		}
	}
}

func (mc *muxCore) tell(ctx context.Context, dst p2p.Addr, c ChannelID, data p2p.IOVec) error {
	data2 := makeMessage(c, data)
	return mc.swarm.Tell(ctx, dst, data2)
}

func (mc *muxCore) ask(ctx context.Context, c ChannelID, resp []byte, dst p2p.Addr, data p2p.IOVec) (int, error) {
	data = makeMessage(c, data)
	return mc.askSwarm.Ask(ctx, resp, dst, data)
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

func (ms *muxedSwarm) Recv(ctx context.Context, src, dst *p2p.Addr, buf []byte) (int, error) {
	return ms.tellHub.Recv(ctx, src, dst, buf)
}

func (ms *muxedSwarm) Ask(ctx context.Context, resp []byte, dst p2p.Addr, data p2p.IOVec) (int, error) {
	return ms.m.ask(ctx, ms.c, resp, dst, data)
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
	ms.tellHub.CloseWithError(p2p.ErrSwarmClosed)
	ms.askHub.CloseWithError(p2p.ErrSwarmClosed)
	return ms.m.close(ms.c)
}

func makeMessage(c ChannelID, data p2p.IOVec) p2p.IOVec {
	header := make([]byte, binary.MaxVarintLen64)
	n := binary.PutUvarint(header, c)
	header = header[:n]

	ret := p2p.IOVec{}
	ret = append(ret, header)
	ret = append(ret, data...)
	return ret
}

func readMessage(data []byte) (ChannelID, []byte, error) {
	c, n := binary.Uvarint(data)
	if n < 1 {
		return 0, nil, errors.Errorf("intmux: could not read message %q", data)
	}
	return c, data[n:], nil
}
