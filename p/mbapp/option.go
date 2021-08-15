package mbapp

import "github.com/sirupsen/logrus"

type Option = func(s *Swarm)

func WithLogger(log *logrus.Logger) Option {
	return func(s *Swarm) {
		s.log = log
	}
}

func WithNumWorkers(n int) Option {
	if n < 1 {
		panic("cannot set workers below 1")
	}
	return func(s *Swarm) {
		s.numWorkers = n
	}
}
