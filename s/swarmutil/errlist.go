package swarmutil

import (
	"github.com/pkg/errors"
)

type ErrList []error

func (ec *ErrList) Do(fn func() error) {
	if err := fn(); err != nil {
		*ec = append(*ec, err)
	}
}

func (ec *ErrList) Add(err error) {
	if err != nil {
		*ec = append(*ec, err)
	}
}

func (ec ErrList) Err() error {
	if len(ec) == 0 {
		return nil
	}
	if len(ec) == 1 {
		return ec[0]
	}
	return errors.Errorf("%v", ec)
}
