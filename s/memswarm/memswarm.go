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
	clock         clockwork.Clock
	latency       time.Duration
	dropRate      float64
	log           *logrus.Logger
	trafficLog    io.Writer
	mtu           int
	bufferedTells int

	mu     sync.RWMutex
	n      int
	swarms map[int]*Swarm
}

func NewRealm(opts ...Option) *Realm {
	r := &Realm{
		clock:         clockwork.NewRealClock(),
		log:           logrus.StandardLogger(),
		trafficLog:    ioutil.Discard,
		mtu:           1 << 20,
		swarms:        make(map[int]*Swarm),
		bufferedTells: 0,
	}
	for _, opt := range opts {
		opt(r)
	}
	return r
}

func (r *Realm) logTraffic(isAsk bool, msg *p2p.Message[Addr]) {
	if r.trafficLog == ioutil.Discard {
		return
	}
	method := "TELL"
	if isAsk {
		method = "ASK_"
	}
	fmt.Fprintf(r.trafficLog, "%s: %v -> %v : %x\n", method, msg.Src, msg.Dst, msg.Payload)
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

		tells: make(chan p2p.Message[Addr], r.bufferedTells),
		asks:  swarmutil.NewAskHub[Addr](),
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

var _ p2p.SecureAskSwarm[Addr] = &Swarm{}

type Swarm struct {
	r          *Realm
	n          int
	privateKey p2p.PrivateKey

	tells chan p2p.Message[Addr]
	asks  *swarmutil.AskHub[Addr]

	mu       sync.RWMutex
	isClosed bool
}

func (s *Swarm) Ask(ctx context.Context, resp []byte, addr Addr, data p2p.IOVec) (int, error) {
	if err := s.checkClosed(); err != nil {
		return 0, err
	}
	msg := p2p.Message[Addr]{
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
	s.r.logTraffic(true, &msg)
	s2 := s.r.getSwarm(addr.N)
	n, err := s2.asks.Deliver(ctx, resp, msg)
	if err != nil {
		return 0, err
	}
	if n < 0 {
		return 0, errors.Errorf("error during ask %v", n)
	}
	return n, nil
}

func (s *Swarm) Tell(ctx context.Context, addr Addr, data p2p.IOVec) error {
	if err := s.checkClosed(); err != nil {
		return err
	}
	if p2p.VecSize(data) > s.r.mtu {
		return p2p.ErrMTUExceeded
	}
	msg := p2p.Message[Addr]{
		Src:     s.LocalAddrs()[0],
		Dst:     addr,
		Payload: p2p.VecBytes(nil, data),
	}
	if !s.r.block() {
		return nil
	}
	s.r.logTraffic(false, &msg)
	s2 := s.r.getSwarm(addr.N)
	if s2 == nil {
		s.r.log.Debugf("swarm %v does not exist in same memswarm.Realm", addr.N)
		return nil
	}
	ctx, cf := context.WithTimeout(ctx, 3*time.Second)
	defer cf()
	select {
	case <-ctx.Done():
		s.r.log.Debugf("memswarm: timeout delivering tell %v -> %v", s.n, addr.N)
		return nil
	case s2.tells <- msg:
		return nil
	}
}

func (s *Swarm) Receive(ctx context.Context, th p2p.TellHandler[Addr]) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	case msg := <-s.tells:
		th(msg)
		return nil
	}
}

func (s *Swarm) ServeAsk(ctx context.Context, fn p2p.AskHandler[Addr]) error {
	return s.asks.ServeAsk(ctx, fn)
}

func (s *Swarm) LocalAddrs() []Addr {
	return []Addr{
		Addr{N: s.n},
	}
}

func (s *Swarm) MTU(context.Context, Addr) int {
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
	s.asks.CloseWithError(p2p.ErrClosed)
	return nil
}

func (s *Swarm) checkClosed() error {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.isClosed {
		return p2p.ErrClosed
	}
	return nil
}

func (s *Swarm) PublicKey() p2p.PublicKey {
	return s.privateKey.Public()
}

func (s *Swarm) LookupPublicKey(ctx context.Context, addr Addr) (p2p.PublicKey, error) {
	s.r.mu.RLock()
	defer s.r.mu.RUnlock()
	other := s.r.swarms[addr.N]
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
