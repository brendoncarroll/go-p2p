package udpswarm

import "runtime"

var defaultNumWorkers = runtime.GOMAXPROCS(0)

type Option func(s *Swarm)

func WithWorkers(n int) Option {
	if n < 1 {
		panic(n)
	}
	return func(s *Swarm) {
		s.numWorkers = n
	}
}
