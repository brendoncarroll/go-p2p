package quicswarm

import "go.brendoncarroll.net/p2p"

type Option[T p2p.Addr] func(s *Swarm[T])

// WithMTU sets the swarm's MTU, if not set it will default to DefaultMTU
func WithMTU[T p2p.Addr](x int) Option[T] {
	return func(s *Swarm[T]) {
		s.mtu = x
	}
}

func WithWhilelist[T p2p.Addr](f func(p2p.Addr) bool) Option[T] {
	return func(s *Swarm[T]) {
		s.allowFunc = f
	}
}

func WithFingerprinter[T p2p.Addr](fp Fingerprinter) Option[T] {
	return func(s *Swarm[T]) {
		s.fingerprinter = fp
	}
}
