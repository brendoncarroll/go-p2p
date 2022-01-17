package wlswarm

import (
	"context"
	"errors"

	"github.com/brendoncarroll/go-p2p"
	"github.com/sirupsen/logrus"
)

var log = p2p.Logger

type AllowFunc[A p2p.Addr] func(addr A) bool

type swarm[A p2p.Addr] struct {
	p2p.SecureSwarm[A]
	af AllowFunc[A]
}

func WrapSecureAsk[A p2p.Addr](x p2p.SecureAskSwarm[A], af AllowFunc[A]) p2p.SecureAskSwarm[A] {
	swarm := &swarm[A]{x, af}
	asker := &asker[A]{x, af}
	return p2p.ComposeSecureAskSwarm[A](swarm, asker, swarm)
}

func WrapSecure[A p2p.Addr](x p2p.SecureSwarm[A], af AllowFunc[A]) p2p.SecureSwarm[A] {
	return &swarm[A]{
		SecureSwarm: x,
		af:          af,
	}
}

func (s *swarm[A]) Tell(ctx context.Context, addr A, data p2p.IOVec) error {
	if checkAddr[A](s, s.af, addr, true) {
		return s.SecureSwarm.Tell(ctx, addr, data)
	}
	return errors.New("address unreachable")
}

func (s *swarm[A]) Receive(ctx context.Context, fn p2p.TellHandler[A]) error {
	for called := false; !called; {
		if err := s.SecureSwarm.Receive(ctx, func(m p2p.Message[A]) {
			if checkAddr[A](s, s.af, m.Src, false) {
				called = true
				fn(m)
			}
		}); err != nil {
			return err
		}
	}
	return nil
}

type asker[A p2p.Addr] struct {
	p2p.SecureAskSwarm[A]
	af AllowFunc[A]
}

func (s *asker[A]) Ask(ctx context.Context, resp []byte, dst A, data p2p.IOVec) (int, error) {
	if checkAddr[A](s, s.af, dst, true) {
		return s.SecureAskSwarm.Ask(ctx, resp, dst, data)
	}
	return 0, errors.New("address unreachable")
}

func (s *asker[A]) ServeAsk(ctx context.Context, fn p2p.AskHandler[A]) error {
	var done bool
	for !done {
		err := s.SecureAskSwarm.ServeAsk(ctx, func(ctx context.Context, resp []byte, m p2p.Message[A]) int {
			if !checkAddr[A](s, s.af, m.Src, false) {
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
func checkAddr[A p2p.Addr](sec p2p.Secure[A], af AllowFunc[A], addr A, isSend bool) bool {
	if !af(addr) {
		if isSend {
			logAttemptSend(addr)
		} else {
			logReceive(addr)
		}
		return false
	}
	return true
}

func logAttemptSend(addr p2p.Addr) {
	data, _ := addr.MarshalText()
	log.WithFields(logrus.Fields{
		"addr": string(data),
	}).Warn("tried to send message to peer not in whitelist")
}

func logReceive(addr p2p.Addr) {
	data, _ := addr.MarshalText()
	log.WithFields(logrus.Fields{
		"addr": string(data),
	}).Warn("recieved message from peer not in whitelist")
}
