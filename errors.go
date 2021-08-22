package p2p

import (
	"errors"
	"net"
)

var (
	ErrMTUExceeded = errors.New("payload is larger than swarms MTU")
	ErrClosed      = net.ErrClosed
)

func IsErrClosed(err error) bool {
	return errors.Is(err, ErrClosed)
}

func IsErrMTUExceeded(err error) bool {
	return errors.Is(err, ErrMTUExceeded)
}
