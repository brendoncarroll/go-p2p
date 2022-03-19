package memswarm

import (
	"strconv"
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

func (s *Swarm) ParseAddr(data []byte) (Addr, error) {
	a := Addr{}
	n, err := strconv.Atoi(string(data))
	if err != nil {
		return Addr{}, err
	}
	a.N = n
	return a, nil
}

func (a Addr) String() string {
	return a.Key()
}
