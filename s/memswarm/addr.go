package memswarm

import (
	"strconv"

	"github.com/brendoncarroll/go-p2p"
)

type Addr struct {
	N int
}

func (a Addr) Key() string {
	return strconv.Itoa(a.N)
}

func (a Addr) MarshalText() ([]byte, error) {
	return []byte(strconv.Itoa(a.N)), nil
}

func (s *Swarm) ParseAddr(data []byte) (p2p.Addr, error) {
	a := Addr{}
	n, err := strconv.Atoi(string(data))
	if err != nil {
		return nil, err
	}
	a.N = n
	return a, nil
}
