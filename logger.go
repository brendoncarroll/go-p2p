package p2p

import (
	"os"
	"strings"

	"github.com/sirupsen/logrus"
)

var (
	log    = logrus.New()
	Logger = log
)

func init() {
	// set level from env
	levels := map[string]logrus.Level{}
	for _, l := range logrus.AllLevels {
		levels[l.String()] = l
	}

	if x, exists := os.LookupEnv("LOG"); exists {
		if level, exists := levels[strings.ToLower(x)]; exists {
			Logger.SetLevel(level)
		}
	}
}
