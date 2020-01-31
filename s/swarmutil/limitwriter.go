package swarmutil

import (
	"errors"
	"io"
)

type LimitWriter struct {
	W     io.Writer
	N     int
	total int
}

func (lw *LimitWriter) Write(p []byte) (n int, err error) {
	if len(p)+lw.total > lw.N {
		return 0, errors.New("write exceeds limit")
	}
	n, err = lw.W.Write(p)
	lw.total += n
	return n, err
}
