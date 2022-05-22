package p2pkeswarm

import (
	"time"

	"github.com/brendoncarroll/go-p2p"
	"github.com/sirupsen/logrus"
)

type Option func(*swarmConfig)

type swarmConfig struct {
	log           logrus.FieldLogger
	fingerprinter p2p.Fingerprinter
	tellTimeout   time.Duration
}

func WithLogger(log logrus.FieldLogger) Option {
	return func(c *swarmConfig) {
		c.log = log
	}
}

func WithFingerprinter(fp p2p.Fingerprinter) Option {
	return func(c *swarmConfig) {
		c.fingerprinter = fp
	}
}
