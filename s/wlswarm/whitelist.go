package wlswarm

import (
	"context"
	"errors"
	"io"

	"github.com/brendoncarroll/go-p2p"
	"github.com/sirupsen/logrus"
)

var log = p2p.Logger

type AllowFunc = func(p2p.PeerID) bool

var _ p2p.SecureSwarm = &swarm{}

type swarm struct {
	p2p.SecureSwarm
	af AllowFunc
}

func WrapSecureAsk(x p2p.SecureAskSwarm, af AllowFunc) p2p.SecureAskSwarm {
	swarm := &swarm{x, af}
	asker := &asker{x, af}
	return p2p.ComposeSecureAskSwarm(swarm, asker, swarm)
}

func WrapSecure(x p2p.SecureSwarm, af AllowFunc) p2p.SecureSwarm {
	return &swarm{
		SecureSwarm: x,
		af:          af,
	}
}

func (s *swarm) Tell(ctx context.Context, addr p2p.Addr, data p2p.IOVec) error {
	if checkAddr(s, s.af, addr, true) {
		return s.SecureSwarm.Tell(ctx, addr, data)
	}
	return errors.New("address unreachable")
}

func (s *swarm) ServeTells(fn p2p.TellHandler) error {
	return s.SecureSwarm.ServeTells(func(m *p2p.Message) {
		if checkAddr(s, s.af, m.Src, false) {
			fn(m)
		}
	})
}

var _ p2p.Asker = &asker{}

type asker struct {
	p2p.SecureAskSwarm
	af AllowFunc
}

func (s *asker) Ask(ctx context.Context, addr p2p.Addr, data p2p.IOVec) ([]byte, error) {
	if checkAddr(s, s.af, addr, true) {
		return s.SecureAskSwarm.Ask(ctx, addr, data)
	}
	return nil, errors.New("address unreachable")
}

func (s *asker) ServeAsks(fn p2p.AskHandler) error {
	return s.SecureAskSwarm.ServeAsks(func(ctx context.Context, m *p2p.Message, w io.Writer) {
		if checkAddr(s, s.af, m.Src, false) {
			fn(ctx, m, w)
		}
	})
}

// checkAddr is called inside TellHandler
func checkAddr(sec p2p.Secure, af AllowFunc, addr p2p.Addr, isSend bool) bool {
	pubKey := p2p.LookupPublicKeyInHandler(sec, addr)
	peerID := p2p.NewPeerID(pubKey)
	if !af(peerID) {
		if isSend {
			logAttemptSend(peerID, addr)
		} else {
			logRecv(peerID, addr)
		}
		return false
	}
	return true
}

func logAttemptSend(id p2p.PeerID, addr p2p.Addr) {
	data, _ := addr.MarshalText()
	log.WithFields(logrus.Fields{
		"peer_id": id,
		"addr":    string(data),
	}).Warn("tried to send message to peer not in whitelist")
}

func logRecv(id p2p.PeerID, addr p2p.Addr) {
	data, _ := addr.MarshalText()
	log.WithFields(logrus.Fields{
		"peer_id": id,
		"addr":    string(data),
	}).Warn("recieved message from peer not in whitelist")
}
