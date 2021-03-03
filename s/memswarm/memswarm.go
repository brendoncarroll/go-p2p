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
	"runtime"
	"sync"
	"time"

	"github.com/brendoncarroll/go-p2p"
	"github.com/brendoncarroll/go-p2p/s/swarmutil"
	"github.com/jonboulle/clockwork"
	"golang.org/x/sync/errgroup"
)

var defaultNumWorkers = runtime.GOMAXPROCS(0)

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
	if x < r.dropRate {
		return false
	}
	return true
}

func (r *Realm) NewSwarm() *Swarm {
	r.mu.Lock()
	defer r.mu.Unlock()
	n := r.n
	r.n++
	s := &Swarm{
		r:          r,
		n:          n,
		privateKey: genPrivateKey(n),

		tellQueue: swarmutil.NewTellQueue(),
		askQueue:  swarmutil.NewAskQueue(),
	}
	r.swarms[n] = s
	return s
}

func (r *Realm) NewSwarmWithKey(privateKey p2p.PrivateKey) *Swarm {
	s := r.NewSwarm()
	s.privateKey = privateKey
	return s
}

func (r *Realm) removeSwarm(s *Swarm) {
	r.mu.Lock()
	delete(r.swarms, s.n)
	defer r.mu.Unlock()
}

var _ p2p.SecureAskSwarm = &Swarm{}

type Swarm struct {
	r          *Realm
	n          int
	privateKey p2p.PrivateKey

	tellQueue *swarmutil.TellQueue
	askQueue  *swarmutil.AskQueue
}

func (s *Swarm) Ask(ctx context.Context, addr p2p.Addr, data p2p.IOVec) ([]byte, error) {
	a := addr.(Addr)
	msg := &p2p.Message{
		Src:     s.LocalAddrs()[0],
		Dst:     addr,
		Payload: p2p.VecBytes(data),
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
	s2.askQueue.DeliverAsk(ctx, msg, lw)
	return buf.Bytes(), nil
}

func (s *Swarm) Tell(ctx context.Context, addr p2p.Addr, data p2p.IOVec) error {
	a := addr.(Addr)
	msg := &p2p.Message{
		Src:     s.LocalAddrs()[0],
		Dst:     addr,
		Payload: p2p.VecBytes(data),
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
	if s2 == nil {
		return nil
	}
	s.r.mu.RUnlock()
	s2.tellQueue.DeliverTell(msg)
	return nil
}

func (s *Swarm) ServeAsks(fn p2p.AskHandler) error {
	ctx := context.Background()
	eg := errgroup.Group{}
	for i := 0; i < defaultNumWorkers; i++ {
		eg.Go(func() error {
			for {
				if err := s.askQueue.ServeAsk(ctx, fn); err != nil {
					return err
				}
			}
		})
	}
	return eg.Wait()
}

func (s *Swarm) ServeTells(fn p2p.TellHandler) error {
	ctx := context.Background()
	eg := errgroup.Group{}
	for i := 0; i < defaultNumWorkers; i++ {
		eg.Go(func() error {
			for {
				if err := s.tellQueue.ServeTell(ctx, fn); err != nil {
					return err
				}
			}
		})
	}
	return eg.Wait()
}

func (s *Swarm) LocalAddrs() []p2p.Addr {
	return []p2p.Addr{Addr{N: s.n}}
}

func (s *Swarm) MTU(context.Context, p2p.Addr) int {
	return s.r.mtu
}

func (s *Swarm) Close() error {
	s.r.removeSwarm(s)
	err := p2p.ErrSwarmClosed
	s.askQueue.CloseWithError(err)
	s.tellQueue.CloseWithError(err)
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
