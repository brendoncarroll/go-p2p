package upnpswarm

import (
	"context"

	"github.com/brendoncarroll/go-p2p"
)

func WrapSwarm(x p2p.Swarm) p2p.Swarm {
	return &Swarm{
		inner: x,
		s:     newService(x),
	}
}

func WrapAsk(x p2p.AskSwarm) p2p.AskSwarm {
	return &AskSwarm{
		inner: x,
		s:     newService(x),
	}
}

func WrapSecure(x p2p.SecureSwarm) p2p.SecureSwarm {
	return p2p.ComposeSecureSwarm(
		WrapSwarm(x),
		x,
	)
}

func WrapSecureAsk(x p2p.SecureAskSwarm) p2p.SecureAskSwarm {
	return &SecureAskSwarm{
		AskSwarm: AskSwarm{
			inner: x,
			s:     newService(x),
		},
		secure: x,
	}
}

type Swarm struct {
	inner p2p.Swarm
	s     *service
}

func (s *Swarm) Tell(ctx context.Context, addr p2p.Addr, data p2p.IOVec) error {
	return s.inner.Tell(ctx, addr, data)
}

func (s *Swarm) Recv(ctx context.Context, src, dst *p2p.Addr, buf []byte) (int, error) {
	return s.inner.Recv(ctx, src, dst, buf)
}

func (s *Swarm) MTU(ctx context.Context, addr p2p.Addr) int {
	return s.inner.MTU(ctx, addr)
}

func (s *Swarm) MaxIncomingSize() int {
	return s.inner.MaxIncomingSize()
}

func (s *Swarm) LocalAddrs() []p2p.Addr {
	return s.s.mapAddrs(s.inner.LocalAddrs())
}

func (s *Swarm) ParseAddr(data []byte) (p2p.Addr, error) {
	return s.inner.ParseAddr(data)
}

func (s *Swarm) Close() error {
	s.s.stop()
	return s.inner.Close()
}

type AskSwarm struct {
	inner p2p.AskSwarm
	s     *service
}

func (s *AskSwarm) Tell(ctx context.Context, addr p2p.Addr, data p2p.IOVec) error {
	return s.inner.Tell(ctx, addr, data)
}

func (s *AskSwarm) Recv(ctx context.Context, src, dst *p2p.Addr, buf []byte) (int, error) {
	return s.inner.Recv(ctx, src, dst, buf)
}

func (s *AskSwarm) Ask(ctx context.Context, resp []byte, addr p2p.Addr, data p2p.IOVec) (int, error) {
	return s.inner.Ask(ctx, resp, addr, data)
}

func (s *AskSwarm) ServeAsk(ctx context.Context, fn p2p.AskHandler) error {
	return s.inner.ServeAsk(ctx, fn)
}

func (s *AskSwarm) MTU(ctx context.Context, addr p2p.Addr) int {
	return s.inner.MTU(ctx, addr)
}

func (s *AskSwarm) MaxIncomingSize() int {
	return s.inner.MaxIncomingSize()
}

func (s *AskSwarm) LocalAddrs() []p2p.Addr {
	return s.s.mapAddrs(s.inner.LocalAddrs())
}

func (s *AskSwarm) Close() error {
	return s.inner.Close()
}

func (s *AskSwarm) ParseAddr(data []byte) (p2p.Addr, error) {
	return s.inner.ParseAddr(data)
}

type SecureAskSwarm struct {
	AskSwarm
	secure p2p.Secure
}

func (s *SecureAskSwarm) LookupPublicKey(ctx context.Context, addr p2p.Addr) (p2p.PublicKey, error) {
	return s.secure.LookupPublicKey(ctx, addr)
}

func (s *SecureAskSwarm) PublicKey() p2p.PublicKey {
	return s.secure.PublicKey()
}
