package noiseswarm

import (
	"fmt"

	"github.com/pkg/errors"
)

// ErrHandshake is returned if there is a problem establishing a connection.
// the sesssion should be cleared if this is returned.
type ErrHandshake struct {
	Message string
	Cause   error
}

func (err *ErrHandshake) Error() string {
	if err.Cause == nil {
		return err.Message
	}
	return fmt.Sprintf("%s: %s", err.Message, err.Cause)
}

// ErrTransport is returned if there was an error decrypting a transport message.
// there will be no plaintext if this is returned, but it does not mean the session
// should be cleared.
type ErrTransport struct {
	Message string
	Num     uint32
}

func (err *ErrTransport) Error() string {
	return fmt.Sprintf("message %d: %s", err.Num, err.Message)
}

var (
	// ErrSessionExpired is returned if the session is either too old or has sent too many messages.
	ErrSessionExpired = errors.Errorf("session has expired")
)

func shouldClearSession(err error) bool {
	switch err.(type) {
	case *ErrHandshake:
		return true
	default:
		return err == ErrSessionExpired
	}
}
