package p2pke

import (
	"fmt"
	"time"
)

type ErrSessionExpired struct {
	ExpiredAt time.Time
}

func (e ErrSessionExpired) Error() string {
	return fmt.Sprintf("p2pke: session expired at %v", e.ExpiredAt)
}
