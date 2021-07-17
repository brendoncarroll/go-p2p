package p2p

import "errors"

var (
	ErrMTUExceeded = errors.New("payload is larger than swarms MTU")
	ErrSwarmClosed = errors.New("swarm closed")
)

func IsErrSwarmClosed(err error) bool {
	return errors.Is(err, ErrSwarmClosed)
}

func IsErrMTUExceeded(err error) bool {
	return errors.Is(err, ErrSwarmClosed)
}
