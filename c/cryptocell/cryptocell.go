package cryptocell

import (
	"github.com/brendoncarroll/go-state/cells"
	"github.com/brendoncarroll/go-state/cells/cryptocell"
)

type Cell cells.Cell

func NewSecretBox(inner Cell, secret []byte) Cell {
	return cryptocell.NewSecretBox(inner, secret)
}
