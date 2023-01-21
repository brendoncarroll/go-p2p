package p2p

import (
	"errors"
	"fmt"
	"net"
)

var (
	ErrMTUExceeded       = errors.New("payload is larger than swarms MTU")
	ErrClosed            = net.ErrClosed
	ErrPublicKeyNotFound = fmt.Errorf("public key not found")
)

func IsErrClosed(err error) bool {
	return errors.Is(err, ErrClosed)
}

func IsErrMTUExceeded(err error) bool {
	return errors.Is(err, ErrMTUExceeded)
}

func IsErrPublicKeyNotFound(err error) bool {
	return errors.Is(err, ErrPublicKeyNotFound)
}
