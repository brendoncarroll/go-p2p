package mbapp

import "golang.org/x/exp/slog"

type swarmConfig struct {
	log        slog.Logger
	numWorkers int
}

type Option = func(c *swarmConfig)

func WithLogger(log slog.Logger) Option {
	return func(c *swarmConfig) {
		c.log = log
	}
}

func WithNumWorkers(n int) Option {
	if n < 1 {
		panic("cannot set workers below 1")
	}
	return func(c *swarmConfig) {
		c.numWorkers = n
	}
}
