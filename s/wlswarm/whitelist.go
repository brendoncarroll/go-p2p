package wlswarm

import (
	"context"
	"errors"

	"github.com/brendoncarroll/go-p2p"
	"github.com/sirupsen/logrus"
)

type AllowFunc[A p2p.Addr] func(addr A) bool

type swarm[A p2p.Addr] struct {
	p2p.SecureSwarm[A]
	af  AllowFunc[A]
	log *logrus.Logger
}

func WrapSecureAsk[A p2p.Addr](x p2p.SecureAskSwarm[A], af AllowFunc[A]) p2p.SecureAskSwarm[A] {
	swarm := &swarm[A]{x, af, logrus.StandardLogger()}
	asker := &asker[A]{x, af, logrus.StandardLogger()}
	return p2p.ComposeSecureAskSwarm[A](swarm, asker, swarm)
}

func WrapSecure[A p2p.Addr](x p2p.SecureSwarm[A], af AllowFunc[A]) p2p.SecureSwarm[A] {
	return &swarm[A]{
		SecureSwarm: x,
		af:          af,
	}
}

func (s *swarm[A]) Tell(ctx context.Context, addr A, data p2p.IOVec) error {
	if checkAddr[A](s, s.log, s.af, addr, true) {
		return s.SecureSwarm.Tell(ctx, addr, data)
	}
	return errors.New("address unreachable")
}

func (s *swarm[A]) Receive(ctx context.Context, fn func(p2p.Message[A])) error {
	for called := false; !called; {
		if err := s.SecureSwarm.Receive(ctx, func(m p2p.Message[A]) {
			if checkAddr[A](s, s.log, s.af, m.Src, false) {
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
	af  AllowFunc[A]
	log *logrus.Logger
}

func (s *asker[A]) Ask(ctx context.Context, resp []byte, dst A, data p2p.IOVec) (int, error) {
	if checkAddr[A](s, s.log, s.af, dst, true) {
		return s.SecureAskSwarm.Ask(ctx, resp, dst, data)
	}
	return 0, errors.New("address unreachable")
}

func (s *asker[A]) ServeAsk(ctx context.Context, fn func(context.Context, []byte, p2p.Message[A]) int) error {
	var done bool
	for !done {
		err := s.SecureAskSwarm.ServeAsk(ctx, func(ctx context.Context, resp []byte, m p2p.Message[A]) int {
			if !checkAddr[A](s, s.log, s.af, m.Src, false) {
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
func checkAddr[A p2p.Addr](sec p2p.Secure[A], log *logrus.Logger, af AllowFunc[A], addr A, isSend bool) bool {
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
