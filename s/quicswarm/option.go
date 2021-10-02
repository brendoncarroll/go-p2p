package quicswarm

import "github.com/brendoncarroll/go-p2p"

type Option func(s *Swarm)

// WithMTU sets the swarm's MTU, if not set it will default to DefaultMTU
func WithMTU(x int) Option {
	return func(s *Swarm) {
		s.mtu = x
	}
}

func WithWhilelist(f func(p2p.Addr) bool) Option {
	return func(s *Swarm) {
		s.allowFunc = f
	}
}

func WithFingerprinter(fp p2p.Fingerprinter) Option {
	return func(s *Swarm) {
		s.fingerprinter = fp
	}
}
