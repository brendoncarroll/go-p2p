// package vswarm implements a virtual swarm which is capable of emulating other types of swarms.
package vswarm

import (
	"context"
	"errors"
	"fmt"
	"log"
	"sync"

	"github.com/brendoncarroll/stdctx/logctx"

	"github.com/brendoncarroll/go-p2p"
	"github.com/brendoncarroll/go-p2p/s/swarmutil"
)

type SecureRealm[A p2p.ComparableAddr, Pub any] struct {
	config    realmConfig[A]
	parseAddr p2p.AddrParser[A]

	mu     sync.RWMutex
	swarms map[A]*SecureSwarm[A, Pub]
}

// NewSecure creates a new SecureRealm
func NewSecure[A p2p.ComparableAddr, Pub any](parseAddr p2p.AddrParser[A], opts ...Option[A]) *SecureRealm[A, Pub] {
	config := defaultRealmConfig[A]()
	for _, opt := range opts {
		opt(&config)
	}
	r := &SecureRealm[A, Pub]{
		config:    config,
		parseAddr: parseAddr,

		swarms: make(map[A]*SecureSwarm[A, Pub]),
	}
	return r
}

// New creates a new SecureSwarm.
// It returns nil if the address is in use.
func (r *SecureRealm[A, Pub]) Create(a A, pub Pub, opts ...SwarmOption[A]) *SecureSwarm[A, Pub] {
	r.mu.Lock()
	defer r.mu.Unlock()
	_, exists := r.swarms[a]
	if exists {
		return nil
	}
	s := &SecureSwarm[A, Pub]{
		r:         r,
		local:     a,
		publicKey: pub,

		tells: swarmutil.NewQueue[A](r.config.queueLen, r.config.mtu),
		asks:  swarmutil.NewAskHub[A](),
	}
	r.swarms[a] = s
	return s
}

func (r *SecureRealm[A, Pub]) Drop(s *SecureSwarm[A, Pub]) {
	if s.r != r {
		panic("drop called with Swarm from a different Realm")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	s2, exists := r.swarms[s.local]
	if !exists || s2 != s {
		panic("swarm is already closed")
	}
	s.tells.Close()
	s.asks.Close()
}

func (r *SecureRealm[A, Pub]) Len() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.swarms)
}

func (r *SecureRealm[A, Pub]) getSwarm(a A) *SecureSwarm[A, Pub] {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.swarms[a]
}

func (r *SecureRealm[A, Pub]) tell(ctx context.Context, src, dst A, v p2p.IOVec) error {
	if p2p.VecSize(v) > r.config.mtu {
		return p2p.ErrMTUExceeded
	}
	s := r.getSwarm(dst)
	onDrop := func() {
		logctx.Debug(ctx, "vswarm: dropping message", logctx.Any("src", src), logctx.Any("dst", dst), logctx.Int("len", p2p.VecSize(v)))
	}
	if s == nil {
		onDrop()
		return nil
	}
	if r.config.tellTransform != nil {
		msg := p2p.Message[A]{
			Src:     src,
			Dst:     dst,
			Payload: p2p.VecBytes(nil, v),
		}
		if r.config.tellTransform(&msg) {
			s.tells.Deliver(msg)
		}
		return nil
	}
	if !s.tells.DeliverVec(src, dst, v) {
		onDrop()
		return nil
	}
	return nil
}

func (r *SecureRealm[A, Pub]) ask(ctx context.Context, resp []byte, src, dst A, v p2p.IOVec) (int, error) {
	s := r.getSwarm(dst)
	onDrop := func() {
		log.Println("dropping")
		logctx.Debug(ctx, "vswarm: dropping ask", logctx.Any("src", src), logctx.Any("dst", dst), logctx.Int("len", p2p.VecSize(v)))
	}
	if s == nil {
		onDrop()
		return 0, errors.New("ask failed: destination unreachable")
	}
	msg := p2p.Message[A]{
		Src:     src,
		Dst:     dst,
		Payload: p2p.VecBytes(nil, v),
	}
	n, err := s.asks.Deliver(ctx, resp, msg)
	if err != nil {
		return 0, err
	}
	if n < 0 {
		return n, fmt.Errorf("error during ask %v", n)
	}
	return n, nil
}

func (r *SecureRealm[A, Pub]) lookupPublicKey(ctx context.Context, target A) (ret Pub, _ error) {
	s := r.getSwarm(target)
	if s == nil {
		return ret, p2p.ErrPublicKeyNotFound
	}
	return s.publicKey, nil
}

func (r *SecureRealm[A, Pub]) mtu(ctx context.Context, target A) int {
	return r.config.mtu
}

type SecureSwarm[A p2p.ComparableAddr, Pub any] struct {
	r         *SecureRealm[A, Pub]
	local     A
	publicKey Pub

	tells swarmutil.Queue[A]
	asks  swarmutil.AskHub[A]
}

func (s *SecureSwarm[A, Pub]) Tell(ctx context.Context, dst A, v p2p.IOVec) error {
	return s.r.tell(ctx, s.local, dst, v)
}

func (s *SecureSwarm[A, Pub]) Receive(ctx context.Context, fn func(p2p.Message[A])) error {
	return s.tells.Receive(ctx, fn)
}

func (s *SecureSwarm[A, Pub]) Ask(ctx context.Context, resp []byte, dst A, v p2p.IOVec) (int, error) {
	return s.r.ask(ctx, resp, s.local, dst, v)
}

func (s *SecureSwarm[A, Pub]) ServeAsk(ctx context.Context, fn func(ctx context.Context, resp []byte, req p2p.Message[A]) int) error {
	return s.asks.ServeAsk(ctx, fn)
}

func (s *SecureSwarm[A, Pub]) LocalAddr() A {
	return s.local
}

func (s *SecureSwarm[A, Pub]) LocalAddrs() []A {
	return []A{s.local}
}

func (s *SecureSwarm[A, Pub]) MTU(ctx context.Context, target A) int {
	return s.r.mtu(ctx, target)
}

func (s *SecureSwarm[A, Pub]) MaxIncomingSize() int {
	return s.r.config.mtu
}

func (s *SecureSwarm[A, Pub]) Close() error {
	s.r.Drop(s)
	return nil
}

func (s *SecureSwarm[A, Pub]) ParseAddr(x []byte) (A, error) {
	return s.r.parseAddr(x)
}

func (s *SecureSwarm[A, Pub]) LookupPublicKey(ctx context.Context, target A) (Pub, error) {
	return s.r.lookupPublicKey(ctx, target)
}

func (s *SecureSwarm[A, Pub]) PublicKey() Pub {
	return s.publicKey
}

type (
	Realm[A p2p.ComparableAddr] SecureRealm[A, struct{}]
	Swarm[A p2p.ComparableAddr] SecureSwarm[A, struct{}]
)

func New[A p2p.ComparableAddr](addrParser p2p.AddrParser[A], opts ...Option[A]) *Realm[A] {
	sr := NewSecure[A, struct{}](addrParser, opts...)
	return (*Realm[A])(sr)
}

func (r *Realm[A]) Create(a A, opts ...SwarmOption[A]) *Swarm[A] {
	sr := (*SecureRealm[A, struct{}])(r).Create(a, struct{}{})
	return (*Swarm[A])(sr)
}

func (r *Realm[A]) Drop(s *Swarm[A]) {
	s2 := (*SecureSwarm[A, struct{}])(s)
	(*SecureRealm[A, struct{}])(r).Drop(s2)
}

func (s *Swarm[A]) Tell(ctx context.Context, dst A, v p2p.IOVec) error {
	ss := (*SecureSwarm[A, struct{}])(s)
	return ss.r.tell(ctx, s.local, dst, v)
}

func (s *Swarm[A]) Receive(ctx context.Context, fn func(p2p.Message[A])) error {
	ss := (*SecureSwarm[A, struct{}])(s)
	return ss.Receive(ctx, fn)
}

func (s *Swarm[A]) Ask(ctx context.Context, resp []byte, dst A, v p2p.IOVec) (int, error) {
	ss := (*SecureSwarm[A, struct{}])(s)
	return ss.Ask(ctx, resp, dst, v)
}

func (s *Swarm[A]) ServeAsk(ctx context.Context, fn func(ctx context.Context, resp []byte, req p2p.Message[A]) int) error {
	ss := (*SecureSwarm[A, struct{}])(s)
	return ss.ServeAsk(ctx, fn)
}

func (s *Swarm[A]) LocalAddr() A {
	ss := (*SecureSwarm[A, struct{}])(s)
	return ss.LocalAddr()
}

func (s *Swarm[A]) LocalAddrs() []A {
	ss := (*SecureSwarm[A, struct{}])(s)
	return ss.LocalAddrs()
}

func (s *Swarm[A]) MaxIncomingSize() int {
	ss := (*SecureSwarm[A, struct{}])(s)
	return ss.MaxIncomingSize()
}

func (s *Swarm[A]) MTU(ctx context.Context, target A) int {
	ss := (*SecureSwarm[A, struct{}])(s)
	return ss.MTU(ctx, target)
}

func (s *Swarm[A]) Close() error {
	ss := (*SecureSwarm[A, struct{}])(s)
	return ss.Close()
}

func (s *Swarm[A]) ParseAddr(x []byte) (A, error) {
	ss := (*SecureSwarm[A, struct{}])(s)
	return ss.ParseAddr(x)
}
