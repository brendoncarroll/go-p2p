package mbapp

import (
	"context"
)

type swarmConfig struct {
	bgCtx      context.Context
	numWorkers int
}

type Option = func(c *swarmConfig)

func WithBackground(ctx context.Context) Option {
	return func(c *swarmConfig) {
		c.bgCtx = ctx
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
