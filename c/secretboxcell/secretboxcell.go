// secretboxcell implements a cell which encrypts the contents using NaCl's secret box
package secretboxcell

import (
	"github.com/brendoncarroll/go-state/cells"
	"github.com/brendoncarroll/go-state/cells/cryptocell"
)

type Cell cells.Cell

func New(inner Cell, secret []byte) Cell {
	return cryptocell.NewSecretBox(inner, secret)
}
