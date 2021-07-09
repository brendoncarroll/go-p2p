package quicswarm

type Option func(s *Swarm)

// WithMTU sets the swarm's MTU, if not set it will default to DefaultMTU
func WithMTU(x int) Option {
	return func(s *Swarm) {
		s.mtu = x
	}
}
