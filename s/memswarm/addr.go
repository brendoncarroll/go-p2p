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

func (a Addr) String() string {
	return a.Key()
}

func ParseAddr(x []byte) (ret Addr, _ error) {
	n, err := strconv.Atoi(string(x))
	if err != nil {
		return Addr{}, err
	}
	ret.N = n
	return ret, nil
}
