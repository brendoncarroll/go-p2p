package dynmux

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log"
	"sync"

	"github.com/brendoncarroll/go-p2p"
	"github.com/google/uuid"
)

const (
	chanMuxReq = 0
	chanMuxRes = 1
)

type Muxer interface {
	Open(x string) (p2p.Swarm, error)
	OpenAsk(x string) (p2p.AskSwarm, error)
	OpenSecure(x string) (p2p.SecureSwarm, error)
	OpenSecureAsk(x string) (p2p.SecureAskSwarm, error)

	LocalAddrs() []p2p.Addr
}

type muxer struct {
	s         p2p.Swarm
	sessionID uuid.UUID

	mu     sync.RWMutex
	i2c    []string
	c2i    map[string]uint32
	swarms []*baseSwarm
	reqs   map[channelKey]chan struct{}

	cache    sync.Map
	sessions sync.Map
}

func MultiplexSwarm(s p2p.Swarm) Muxer {
	m := &muxer{
		s:         s,
		sessionID: uuid.New(),

		i2c: []string{
			"MUX_REQ",
			"MUX_RES",
		},
		c2i: map[string]uint32{},
		swarms: []*baseSwarm{
			nil,
			nil,
		},
		reqs: map[channelKey]chan struct{}{},
	}

	s.OnTell(m.handleTell)
	if asker, ok := s.(p2p.Asker); ok {
		asker.OnAsk(m.handleAsk)
	}

	return m
}

func (m *muxer) LocalAddrs() []p2p.Addr {
	return m.s.LocalAddrs()
}

func (m *muxer) handleTell(msg *p2p.Message) {
	ctx := context.TODO()
	msg2 := Message(msg.Payload)
	if err := msg2.Validate(); err != nil {
		log.Println(err)
		return
	}

	c := msg2.GetChannel()
	switch c {
	case 0:
		data := msg2.GetData()
		req := MuxReq{}
		if err := json.Unmarshal(data, &req); err != nil {
			log.Println(err)
		}

		m.mu.RLock()
		i := m.c2i[req.Name]
		m.mu.RUnlock()

		resMsg := newMuxRes(m.sessionID, req.Name, i)
		m.s.Tell(ctx, msg.Src, []byte(resMsg))

	case 1:
		data := msg2.GetData()
		res := MuxRes{}
		if err := json.Unmarshal(data, &res); err != nil {
			log.Println(err)
		}
		ck := newChannelKey(msg.Src, res.Name)

		// check with a read lock first
		m.mu.RLock()
		if _, exists := m.reqs[ck]; !exists {
			m.mu.RUnlock()
			return
		}
		m.mu.RUnlock()

		m.updateSession(msg.Src, res.SessionID)

		m.mu.Lock()
		if ch, exists := m.reqs[ck]; exists {
			m.putChannel(ck, res.Index)
			delete(m.reqs, ck)
			close(ch)
		}
		m.mu.Unlock()

	default:
		if int(c) < len(m.swarms) {
			msg.Payload = msg2.GetData()
			s := m.swarms[c]
			if s != nil {
				s.handleTell(msg)
			}
		}
	}
}

func (m *muxer) handleAsk(ctx context.Context, msg *p2p.Message, w io.Writer) {
	msg2 := Message(msg.Payload)
	if err := msg2.Validate(); err != nil {
		log.Println(err)
		return
	}

	c := msg2.GetChannel()
	if c < 2 {
		return
	}
	if int(c) >= len(m.swarms) {
		return
	}
	s := m.swarms[c]

	msg = &p2p.Message{
		Src:     msg.Src,
		Dst:     msg.Dst,
		Payload: msg2.GetData(),
	}
	s.handleAsk(ctx, msg, w)
}

func (m *muxer) Open(x string) (p2p.Swarm, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	_, exists := m.c2i[x]
	if exists {
		return nil, errors.New("swarm already exists")
	}

	i := uint32(len(m.i2c))
	s := newSwarm(m, x)

	m.c2i[x] = i
	m.i2c = append(m.i2c, x)
	m.swarms = append(m.swarms, s)
	return s, nil
}

func (m *muxer) OpenAsk(x string) (p2p.AskSwarm, error) {
	_ = m.s.(p2p.AskSwarm)

	s, err := m.Open(x)
	if err != nil {
		return nil, err
	}

	return p2p.ComposeAskSwarm(s, s.(p2p.Asker)), nil
}

func (m *muxer) OpenSecure(x string) (p2p.SecureSwarm, error) {
	sec := m.s.(p2p.SecureSwarm)

	s, err := m.Open(x)
	if err != nil {
		return nil, err
	}
	return p2p.ComposeSecureSwarm(s, sec), nil
}

func (m *muxer) OpenSecureAsk(x string) (p2p.SecureAskSwarm, error) {
	sec := m.s.(p2p.SecureAskSwarm)

	s, err := m.Open(x)
	if err != nil {
		return nil, err
	}

	return p2p.ComposeSecureAskSwarm(s, s.(p2p.Asker), sec), nil
}

func (m *muxer) Close() error {
	return m.s.Close()
}

func (m *muxer) lookup(ctx context.Context, addr p2p.Addr, name string) (uint32, error) {
	ck := newChannelKey(addr, name)
	i := m.getChannel(ck)
	if i > 0 {
		return i, nil
	}

	m.mu.Lock()
	ch, exists := m.reqs[ck]
	if !exists {
		ch = make(chan struct{})
		m.reqs[ck] = ch
	}
	m.mu.Unlock()

	if !exists {
		msg := newMuxReq(name)
		if err := m.s.Tell(ctx, addr, msg); err != nil {
			return 0, nil
		}
	}

	select {
	case <-ch:
		i := m.getChannel(ck)
		if i == 0 {
			return 0, errors.New("could not get channel")
		}
		return i, nil
	case <-ctx.Done():
		m.mu.Lock()
		delete(m.reqs, ck)
		m.mu.Unlock()
		return 0, ctx.Err()
	}
}

func (m *muxer) getChannel(ck channelKey) uint32 {
	v, exists := m.cache.Load(ck)
	if !exists {
		return 0
	}
	return v.(uint32)
}

func (m *muxer) putChannel(ck channelKey, i uint32) {
	m.cache.Store(ck, i)
}

func (m *muxer) putSession(addr p2p.Addr, sessionID uuid.UUID) {
	m.sessions.Store(addr.Key(), sessionID)
}

func (m *muxer) getSession(addr p2p.Addr) uuid.UUID {
	v, ok := m.sessions.Load(addr.Key())
	if !ok {
		return uuid.UUID{}
	}
	return v.(uuid.UUID)
}

func (m *muxer) updateSession(addr p2p.Addr, sessionID uuid.UUID) {
	current := m.getSession(addr)
	if current != sessionID {
		m.putSession(addr, sessionID)
		m.cache.Range(func(key, value interface{}) bool {
			if key == addr.Key() && value.(uuid.UUID) != sessionID {
				m.cache.Delete(key)
			}
			return true
		})
	}
}

type channelKey struct {
	AddrKey string
	Channel string
}

func newChannelKey(addr p2p.Addr, name string) channelKey {
	return channelKey{
		AddrKey: addr.Key(),
		Channel: name,
	}
}
