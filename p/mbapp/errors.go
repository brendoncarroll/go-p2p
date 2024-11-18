package mbapp

import (
	"fmt"

	"go.brendoncarroll.net/p2p"
)

type AppError struct {
	Addr     p2p.Addr
	Code     uint8
	Request  []byte
	Response []byte
}

func (e AppError) Error() string {
	return fmt.Sprintf("ADDR: %v REQ: %q RES: %q", e.Addr, e.Request, e.Response)
}
