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

type askSwarm struct {
	p2p.SecureAskSwarm
	af AllowFunc
}

func WrapSecureAsk(x p2p.SecureAskSwarm, af AllowFunc) p2p.SecureAskSwarm {
	return &askSwarm{
		SecureAskSwarm: x,
		af:             af,
	}
}

func (s *askSwarm) Tell(ctx context.Context, addr p2p.Addr, data []byte) error {
	if s.checkAddr(addr, true) {
		return s.SecureAskSwarm.Tell(ctx, addr, data)
	}
	return errors.New("address unreachable")
}

func (s *askSwarm) OnTell(fn p2p.TellHandler) {
	s.SecureAskSwarm.OnTell(func(m *p2p.Message) {
		if s.checkAddr(m.Src, false) {
			fn(m)
		}
	})
}

func (s *askSwarm) Ask(ctx context.Context, addr p2p.Addr, data []byte) ([]byte, error) {
	if s.checkAddr(addr, true) {
		return s.SecureAskSwarm.Ask(ctx, addr, data)
	}
	return nil, errors.New("address unreachable")
}

func (s *askSwarm) OnAsk(fn p2p.AskHandler) {
	s.SecureAskSwarm.OnAsk(func(ctx context.Context, m *p2p.Message, w io.Writer) {
		if s.checkAddr(m.Src, false) {
			fn(ctx, m, w)
		}
	})
}

func (s *askSwarm) checkAddr(addr p2p.Addr, isSend bool) bool {
	peerID := p2p.LookupPeerID(s, addr)
	if peerID == nil || !s.af(*peerID) {
		if isSend {
			logAttemptSend(peerID, addr)
		} else {
			logRecv(peerID, addr)
		}
		return false
	}
	return true
}

func logAttemptSend(id *p2p.PeerID, addr p2p.Addr) {
	data, _ := addr.MarshalText()
	log.WithFields(logrus.Fields{
		"peer_id": id,
		"addr":    string(data),
	}).Warn("tried to send message to peer not in whitelist")
}

func logRecv(id *p2p.PeerID, addr p2p.Addr) {
	data, _ := addr.MarshalText()
	log.WithFields(logrus.Fields{
		"peer_id": id,
		"addr":    string(data),
	}).Warn("recieved message from peer not in whitelist")
}
