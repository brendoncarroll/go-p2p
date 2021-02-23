package memswarm

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"math/rand"
	"sync"
	"time"

	"github.com/brendoncarroll/go-p2p"
	"github.com/brendoncarroll/go-p2p/s/swarmutil"
	"github.com/jonboulle/clockwork"
)

type Realm struct {
	clock    clockwork.Clock
	latency  time.Duration
	dropRate float64
	logw     io.Writer
	mtu      int

	mu     sync.RWMutex
	swarms []*Swarm
}

func NewRealm(opts ...Option) *Realm {
	r := &Realm{
		clock: clockwork.NewRealClock(),
		logw:  ioutil.Discard,
		mtu:   1 << 20,
	}
	for _, opt := range opts {
		opt(r)
	}
	return r
}

func (r *Realm) log(isAsk bool, msg *p2p.Message) {
	method := "TELL"
	if isAsk {
		method = "ASK_"
	}
	s := fmt.Sprintf("%s: %v -> %v : %x\n", method, msg.Src, msg.Dst, msg.Payload)
	r.logw.Write([]byte(s))
}

func (r *Realm) block() bool {
	if r.latency > 0 {
		r.clock.Sleep(r.latency)
	}
	x := rand.Float64()
	if x < r.dropRate {
		return false
	}
	return true
}

func (r *Realm) NewSwarm() *Swarm {
	n := len(r.swarms)
	s := &Swarm{
		r:          r,
		n:          n,
		privateKey: genPrivateKey(n),
	}
	r.mu.Lock()
	r.swarms = append(r.swarms, s)
	r.mu.Unlock()

	return s
}

func (r *Realm) NewSwarmWithKey(privateKey p2p.PrivateKey) *Swarm {
	s := r.NewSwarm()
	s.privateKey = privateKey
	return s
}

var _ p2p.SecureAskSwarm = &Swarm{}

type Swarm struct {
	r          *Realm
	n          int
	privateKey p2p.PrivateKey

	thCell swarmutil.THCell
	ahCell swarmutil.AHCell
}

func (s *Swarm) Ask(ctx context.Context, addr p2p.Addr, data []byte) ([]byte, error) {
	a := addr.(Addr)
	msg := &p2p.Message{
		Src:     s.LocalAddrs()[0],
		Dst:     addr,
		Payload: data,
	}
	if len(data) > s.r.mtu {
		return nil, p2p.ErrMTUExceeded
	}
	if !s.r.block() {
		return nil, errors.New("message dropped")
	}
	s.r.log(true, msg)
	buf := bytes.Buffer{}
	lw := &swarmutil.LimitWriter{W: &buf, N: s.r.mtu}
	s.r.mu.RLock()
	s2 := s.r.swarms[a.N]
	s.r.mu.RUnlock()
	s2.ahCell.Handle(ctx, msg, lw)
	return buf.Bytes(), nil
}

func (s *Swarm) Tell(ctx context.Context, addr p2p.Addr, data []byte) error {
	a := addr.(Addr)
	msg := &p2p.Message{
		Src:     s.LocalAddrs()[0],
		Dst:     addr,
		Payload: data,
	}
	if len(data) > s.r.mtu {
		return p2p.ErrMTUExceeded
	}
	if !s.r.block() {
		return nil
	}
	s.r.log(false, msg)
	s.r.mu.RLock()
	s2 := s.r.swarms[a.N]
	s.r.mu.RUnlock()
	s2.thCell.Handle(msg)
	return nil
}

func (s *Swarm) OnAsk(fn p2p.AskHandler) {
	s.ahCell.Set(fn)
}

func (s *Swarm) OnTell(fn p2p.TellHandler) {
	s.thCell.Set(fn)
}

func (s *Swarm) LocalAddrs() []p2p.Addr {
	return []p2p.Addr{Addr{N: s.n}}
}

func (s *Swarm) MTU(context.Context, p2p.Addr) int {
	return s.r.mtu
}

func (s *Swarm) Close() error {
	s.OnAsk(nil)
	s.OnTell(nil)
	return nil
}

func (s *Swarm) PublicKey() p2p.PublicKey {
	return s.privateKey.Public()
}

func (s *Swarm) LookupPublicKey(ctx context.Context, addr p2p.Addr) (p2p.PublicKey, error) {
	a := addr.(Addr)
	s.r.mu.RLock()
	defer s.r.mu.RUnlock()
	if len(s.r.swarms) <= a.N {
		return nil, p2p.ErrPublicKeyNotFound
	}
	other := s.r.swarms[a.N]
	return other.privateKey.Public(), nil
}

func genPrivateKey(i int) ed25519.PrivateKey {
	seed := make([]byte, ed25519.SeedSize)
	binary.BigEndian.PutUint64(seed[len(seed)-8:], uint64(i))
	return ed25519.NewKeyFromSeed(seed)
}
