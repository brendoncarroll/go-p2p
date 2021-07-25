package wlswarm

import (
	"context"
	"errors"

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

func (s *swarm) Receive(ctx context.Context, src, dst *p2p.Addr, buf []byte) (int, error) {
	for {
		n, err := s.SecureSwarm.Receive(ctx, src, dst, buf)
		if err != nil {
			return 0, err
		}
		if checkAddr(s, s.af, *src, false) {
			return n, err
		}
	}
}

var _ p2p.Asker = &asker{}

type asker struct {
	p2p.SecureAskSwarm
	af AllowFunc
}

func (s *asker) Ask(ctx context.Context, resp []byte, dst p2p.Addr, data p2p.IOVec) (int, error) {
	if checkAddr(s, s.af, dst, true) {
		return s.SecureAskSwarm.Ask(ctx, resp, dst, data)
	}
	return 0, errors.New("address unreachable")
}

func (s *asker) ServeAsk(ctx context.Context, fn p2p.AskHandler) error {
	var done bool
	for !done {
		err := s.SecureAskSwarm.ServeAsk(ctx, func(ctx context.Context, resp []byte, m p2p.Message) (int, error) {
			if !checkAddr(s, s.af, m.Src, false) {
				return 0, nil
			}
			done = true
			return fn(ctx, resp, m)
		})
		if err != nil {
			return err
		}
	}
	return nil
}

// checkAddr is called inside TellHandler
func checkAddr(sec p2p.Secure, af AllowFunc, addr p2p.Addr, isSend bool) bool {
	pubKey := p2p.LookupPublicKeyInHandler(sec, addr)
	peerID := p2p.NewPeerID(pubKey)
	if !af(peerID) {
		if isSend {
			logAttemptSend(peerID, addr)
		} else {
			logReceive(peerID, addr)
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

func logReceive(id p2p.PeerID, addr p2p.Addr) {
	data, _ := addr.MarshalText()
	log.WithFields(logrus.Fields{
		"peer_id": id,
		"addr":    string(data),
	}).Warn("recieved message from peer not in whitelist")
}
