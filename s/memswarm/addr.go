package memswarm

import "strconv"

type Addr struct {
	N int
}

func (a Addr) Key() string {
	return strconv.Itoa(a.N)
}

func (a *Addr) MarshalText() ([]byte, error) {
	return []byte(strconv.Itoa(a.N)), nil
}

func (a *Addr) UnmarshalText(data []byte) error {
	n, err := strconv.Atoi(string(data))
	if err != nil {
		return err
	}
	a.N = n
	return nil
}
