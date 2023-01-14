package memswarm

import (
	"context"
	"crypto/ed25519"
	"encoding/binary"
	"fmt"
	"io"
	"io/ioutil"
	"sync"

	"github.com/brendoncarroll/go-p2p"
	"github.com/brendoncarroll/go-p2p/s/swarmutil"
	"github.com/brendoncarroll/stdctx/logctx"
	"github.com/jonboulle/clockwork"
	"github.com/pkg/errors"
	"golang.org/x/exp/slog"
)

type Message = p2p.Message[Addr]

type Realm[Pub any] struct {
	ctx           context.Context
	clock         clockwork.Clock
	trafficLog    io.Writer
	tellTransform func(*Message) bool
	mtu           int
	bufferedTells int

	mu     sync.RWMutex
	n      int
	swarms map[int]*Swarm[Pub]
}

func NewRealm[Pub any](opts ...Option[Pub]) *Realm[Pub] {
	r := &Realm[Pub]{
		ctx:           context.Background(),
		clock:         clockwork.NewRealClock(),
		trafficLog:    ioutil.Discard,
		tellTransform: func(x *Message) bool { return true },
		mtu:           1 << 20,
		swarms:        make(map[int]*Swarm[Pub]),
		bufferedTells: 0,
	}
	for _, opt := range opts {
		opt(r)
	}
	return r
}

func (r *Realm[Pub]) logTraffic(isAsk bool, msg *p2p.Message[Addr]) {
	if r.trafficLog == ioutil.Discard {
		return
	}
	method := "TELL"
	if isAsk {
		method = "ASK_"
	}
	fmt.Fprintf(r.trafficLog, "%s: %v -> %v : %x\n", method, msg.Src, msg.Dst, msg.Payload)
}

func (r *Realm[Pub]) NewSwarm() *Swarm[Pub] {
	var zero Pub
	return r.NewSwarmWithKey(zero)
}

func (r *Realm[Pub]) NewSwarmWithKey(publicKey Pub) *Swarm[Pub] {
	r.mu.Lock()
	defer r.mu.Unlock()
	n := r.n
	r.n++
	s := &Swarm[Pub]{
		r:           r,
		n:           n,
		localPublic: publicKey,

		tells: make(chan p2p.Message[Addr], r.bufferedTells),
		asks:  swarmutil.NewAskHub[Addr](),
	}
	r.swarms[n] = s
	return s
}

func (r *Realm[Pub]) removeSwarm(s *Swarm[Pub]) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.swarms, s.n)
}

func (r *Realm[Pub]) getSwarm(i int) *Swarm[Pub] {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.swarms[i]
}

var _ p2p.SecureAskSwarm[Addr, struct{}] = &Swarm[struct{}]{}

type Swarm[Pub any] struct {
	r           *Realm[Pub]
	n           int
	localPublic Pub

	tells chan p2p.Message[Addr]
	asks  *swarmutil.AskHub[Addr]

	mu       sync.RWMutex
	isClosed bool
}

func (s *Swarm[Pub]) Ask(ctx context.Context, resp []byte, addr Addr, data p2p.IOVec) (int, error) {
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

func (s *Swarm[Pub]) Tell(ctx context.Context, dst Addr, data p2p.IOVec) error {
	if err := s.checkClosed(); err != nil {
		return err
	}
	if p2p.VecSize(data) > s.r.mtu {
		return p2p.ErrMTUExceeded
	}
	msg := &p2p.Message[Addr]{
		Src:     s.LocalAddrs()[0],
		Dst:     dst,
		Payload: p2p.VecBytes(nil, data),
	}
	if !s.r.tellTransform(msg) {
		return nil
	}
	s.r.logTraffic(false, msg)
	s2 := s.r.getSwarm(dst.N)
	if s2 == nil {
		logctx.Debug(s.r.ctx, "swarm does not exist in same memswarm.Realm", slog.Any("dst", dst.N))
		return nil
	}
	select {
	case <-ctx.Done():
		logctx.Debug(s.r.ctx, "memswarm: timeout delivering tell", slog.Any("src", s.n), slog.Any("dst", dst.N))
		return nil
	case s2.tells <- *msg:
		return nil
	}
}

func (s *Swarm[Pub]) Receive(ctx context.Context, th func(p2p.Message[Addr])) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	case msg := <-s.tells:
		th(msg)
		return nil
	}
}

func (s *Swarm[Pub]) ServeAsk(ctx context.Context, fn func(context.Context, []byte, p2p.Message[Addr]) int) error {
	return s.asks.ServeAsk(ctx, fn)
}

func (s *Swarm[Pub]) LocalAddrs() []Addr {
	return []Addr{
		{N: s.n},
	}
}

func (s *Swarm[Pub]) MTU(context.Context, Addr) int {
	return s.r.mtu
}

func (s *Swarm[Pub]) MaxIncomingSize() int {
	return s.r.mtu
}

func (s *Swarm[Pub]) Close() error {
	s.mu.Lock()
	s.isClosed = true
	s.mu.Unlock()
	s.r.removeSwarm(s)
	s.asks.CloseWithError(p2p.ErrClosed)
	return nil
}

func (s *Swarm[Pub]) checkClosed() error {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.isClosed {
		return p2p.ErrClosed
	}
	return nil
}

func (s *Swarm[Pub]) PublicKey() Pub {
	return s.localPublic
}

func (s *Swarm[Pub]) LookupPublicKey(ctx context.Context, addr Addr) (Pub, error) {
	s.r.mu.RLock()
	defer s.r.mu.RUnlock()
	other := s.r.swarms[addr.N]
	if other == nil {
		var zero Pub
		return zero, p2p.ErrPublicKeyNotFound
	}
	return other.localPublic, nil
}

func (s *Swarm[Pub]) String() string {
	return fmt.Sprintf("MemSwarm@%p", s)
}

func genPrivateKey(i int) ed25519.PrivateKey {
	seed := make([]byte, ed25519.SeedSize)
	binary.BigEndian.PutUint64(seed[len(seed)-8:], uint64(i))
	return ed25519.NewKeyFromSeed(seed)
}
