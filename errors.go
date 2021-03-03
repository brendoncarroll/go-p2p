package p2p

import "errors"

var (
	ErrMTUExceeded = errors.New("payload is larger than swarms MTU")
	ErrSwarmClosed = errors.New("swarm closed")
)
