package p2p

import (
	"context"
	"errors"
)

// Cell is a compare-and-swap cell
type Cell interface {
	// CAS sets the contents of the cell to next, IFF current equals the cell contents.
	// returns whether or not the swap was successful, the actual value in the cell, or an error
	// if err != nil then success must be false.
	// the swap failing is not considered an error.
	CAS(ctx context.Context, current, next []byte) (success bool, actual []byte, err error)

	// Get retrieves the contents of the cell.
	// If err != nil the data returned is invalid.
	Get(ctx context.Context) (data []byte, err error)
}

func Apply(ctx context.Context, cell Cell, fn func([]byte) ([]byte, error)) error {
	const MAX = 10

	var (
		err     error
		current []byte
		success bool
	)
	for i := 0; i < MAX; i++ {
		current, err = cell.Get(ctx)
		if err != nil {
			return err
		}
		next, err := fn(current)
		if err != nil {
			return err
		}
		success, current, err = cell.CAS(ctx, current, next)
		if err != nil {
			return err
		}
		if success {
			return nil
		}
	}

	return errors.New("cell CAS attempts maxed out")
}
