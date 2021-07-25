package memswarm

import (
	"context"
	"crypto/ed25519"
	"encoding/binary"
	"fmt"
	"io"
	"io/ioutil"
	"math/rand"
	"sync"
	"time"

	"github.com/brendoncarroll/go-p2p"
	"github.com/brendoncarroll/go-p2p/s/swarmutil"
	"github.com/jonboulle/clockwork"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
)

type Realm struct {
	clock    clockwork.Clock
	latency  time.Duration
	dropRate float64
	logw     io.Writer
	mtu      int

	mu     sync.RWMutex
	n      int
	swarms map[int]*Swarm
}

func NewRealm(opts ...Option) *Realm {
	r := &Realm{
		clock:  clockwork.NewRealClock(),
		logw:   ioutil.Discard,
		mtu:    1 << 20,
		swarms: make(map[int]*Swarm),
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
	return x >= r.dropRate
}

func (r *Realm) NewSwarm() *Swarm {
	return r.NewSwarmWithKey(nil)
}

func (r *Realm) NewSwarmWithKey(privateKey p2p.PrivateKey) *Swarm {
	r.mu.Lock()
	defer r.mu.Unlock()
	n := r.n
	r.n++
	if privateKey == nil {
		privateKey = genPrivateKey(n)
	}
	s := &Swarm{
		r:          r,
		n:          n,
		privateKey: privateKey,

		tells: swarmutil.NewTellHub(),
		asks:  swarmutil.NewAskHub(),
	}
	r.swarms[n] = s
	return s
}

func (r *Realm) removeSwarm(s *Swarm) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.swarms, s.n)
}

func (r *Realm) getSwarm(i int) *Swarm {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.swarms[i]
}

var _ p2p.SecureAskSwarm = &Swarm{}

type Swarm struct {
	r          *Realm
	n          int
	privateKey p2p.PrivateKey

	tells *swarmutil.TellHub
	asks  *swarmutil.AskHub

	mu       sync.RWMutex
	isClosed bool
}

func (s *Swarm) Ask(ctx context.Context, resp []byte, addr p2p.Addr, data p2p.IOVec) (int, error) {
	if err := s.checkClosed(); err != nil {
		return 0, err
	}
	a := addr.(Addr)
	msg := p2p.Message{
		Src:     s.LocalAddrs()[0],
		Dst:     addr,
		Payload: p2p.VecBytes(nil, data),
	}
	if p2p.VecSize(data) > s.r.mtu {
		return 0, p2p.ErrMTUExceeded
	}
	if !s.r.block() {
		return 0, errors.New("message dropped")
	}
	s.r.log(true, &msg)
	s2 := s.r.getSwarm(a.N)
	return s2.asks.Deliver(ctx, resp, msg)
}

func (s *Swarm) Tell(ctx context.Context, addr p2p.Addr, data p2p.IOVec) error {
	if err := s.checkClosed(); err != nil {
		return err
	}
	a := addr.(Addr)
	if p2p.VecSize(data) > s.r.mtu {
		return p2p.ErrMTUExceeded
	}
	msg := p2p.Message{
		Src:     s.LocalAddrs()[0],
		Dst:     addr,
		Payload: p2p.VecBytes(nil, data),
	}
	if !s.r.block() {
		return nil
	}
	s.r.log(false, &msg)
	s2 := s.r.getSwarm(a.N)
	if s2 == nil {
		logrus.Warnf("swarm %v does not exist in same memswarm.Realm", a.N)
		return nil
	}
	ctx, cf := context.WithTimeout(ctx, 3*time.Second)
	defer cf()
	if err := s2.tells.Deliver(ctx, msg); err != nil {
		logrus.Warnf("error delivering tell %v -> %v: %v", s.n, a.N, err)
	}
	return nil
}

func (s *Swarm) Receive(ctx context.Context, src, dst *p2p.Addr, buf []byte) (int, error) {
	return s.tells.Receive(ctx, src, dst, buf)
}

func (s *Swarm) ServeAsk(ctx context.Context, fn p2p.AskHandler) error {
	return s.asks.ServeAsk(ctx, fn)
}

func (s *Swarm) LocalAddrs() []p2p.Addr {
	return []p2p.Addr{
		Addr{N: s.n},
	}
}

func (s *Swarm) MTU(context.Context, p2p.Addr) int {
	return s.r.mtu
}

func (s *Swarm) MaxIncomingSize() int {
	return s.r.mtu
}

func (s *Swarm) Close() error {
	s.mu.Lock()
	s.isClosed = true
	s.mu.Unlock()
	s.r.removeSwarm(s)
	s.asks.CloseWithError(p2p.ErrSwarmClosed)
	s.tells.CloseWithError(p2p.ErrSwarmClosed)
	return nil
}

func (s *Swarm) checkClosed() error {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.isClosed {
		return p2p.ErrSwarmClosed
	}
	return nil
}

func (s *Swarm) PublicKey() p2p.PublicKey {
	return s.privateKey.Public()
}

func (s *Swarm) LookupPublicKey(ctx context.Context, addr p2p.Addr) (p2p.PublicKey, error) {
	a := addr.(Addr)
	s.r.mu.RLock()
	defer s.r.mu.RUnlock()
	other := s.r.swarms[a.N]
	if other == nil {
		return nil, p2p.ErrPublicKeyNotFound
	}
	return other.privateKey.Public(), nil
}

func (s *Swarm) String() string {
	return fmt.Sprintf("MemSwarm@%p", s)
}

func genPrivateKey(i int) ed25519.PrivateKey {
	seed := make([]byte, ed25519.SeedSize)
	binary.BigEndian.PutUint64(seed[len(seed)-8:], uint64(i))
	return ed25519.NewKeyFromSeed(seed)
}
