package wlswarm

import (
	"context"
	"errors"

	"github.com/brendoncarroll/go-p2p"
	"github.com/sirupsen/logrus"
)

type AllowFunc = func(addr p2p.Addr) bool

var _ p2p.SecureSwarm = &swarm{}

type swarm struct {
	p2p.SecureSwarm
	af  AllowFunc
	log *logrus.Logger
}

func WrapSecureAsk(x p2p.SecureAskSwarm, af AllowFunc) p2p.SecureAskSwarm {
	swarm := &swarm{x, af, logrus.StandardLogger()}
	asker := &asker{x, af, logrus.StandardLogger()}
	return p2p.ComposeSecureAskSwarm(swarm, asker, swarm)
}

func WrapSecure(x p2p.SecureSwarm, af AllowFunc) p2p.SecureSwarm {
	return &swarm{
		SecureSwarm: x,
		af:          af,
	}
}

func (s *swarm) Tell(ctx context.Context, addr p2p.Addr, data p2p.IOVec) error {
	if checkAddr(s, s.log, s.af, addr, true) {
		return s.SecureSwarm.Tell(ctx, addr, data)
	}
	return errors.New("address unreachable")
}

func (s *swarm) Receive(ctx context.Context, fn p2p.TellHandler) error {
	for called := false; !called; {
		if err := s.SecureSwarm.Receive(ctx, func(m p2p.Message) {
			if checkAddr(s, s.log, s.af, m.Src, false) {
				called = true
				fn(m)
			}
		}); err != nil {
			return err
		}
	}
	return nil
}

var _ p2p.Asker = &asker{}

type asker struct {
	p2p.SecureAskSwarm
	af  AllowFunc
	log *logrus.Logger
}

func (s *asker) Ask(ctx context.Context, resp []byte, dst p2p.Addr, data p2p.IOVec) (int, error) {
	if checkAddr(s, s.log, s.af, dst, true) {
		return s.SecureAskSwarm.Ask(ctx, resp, dst, data)
	}
	return 0, errors.New("address unreachable")
}

func (s *asker) ServeAsk(ctx context.Context, fn p2p.AskHandler) error {
	var done bool
	for !done {
		err := s.SecureAskSwarm.ServeAsk(ctx, func(ctx context.Context, resp []byte, m p2p.Message) int {
			if !checkAddr(s, s.log, s.af, m.Src, false) {
				return -1
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
func checkAddr(sec p2p.Secure, log *logrus.Logger, af AllowFunc, addr p2p.Addr, isSend bool) bool {
	if !af(addr) {
		if isSend {
			logAttemptSend(log, addr)
		} else {
			logReceive(log, addr)
		}
		return false
	}
	return true
}

func logAttemptSend(log *logrus.Logger, addr p2p.Addr) {
	data, _ := addr.MarshalText()
	log.WithFields(logrus.Fields{
		"addr": string(data),
	}).Warn("tried to send message to peer not in whitelist")
}

func logReceive(log *logrus.Logger, addr p2p.Addr) {
	data, _ := addr.MarshalText()
	log.WithFields(logrus.Fields{
		"addr": string(data),
	}).Warn("recieved message from peer not in whitelist")
}
