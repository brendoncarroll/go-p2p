package p2p

import (
	"encoding/json"
)

type Addr interface {
	Key() string
	MarshalText() ([]byte, error)
	UnmarshalText([]byte) error
}

type AddrList []Addr

func (al AddrList) Key() string {
	data, _ := al.MarshalText()
	return string(data)
}

func (al AddrList) MarshalText() ([]byte, error) {
	items := make([]string, len(al))
	for i := range al {
		data, err := al[i].MarshalText()
		if err != nil {
			return nil, err
		}
		items[i] = string(data)
	}
	return json.Marshal(items)
}

func (al *AddrList) UnmarshalText(data []byte) error {
	items := []string{}
	if err := json.Unmarshal(data, &items); err != nil {
		return err
	}
	for _, item := range items {
		*al = append(*al, TextAddr(item))
	}
	return nil
}

type TextAddr []byte

func (a TextAddr) MarshalText() ([]byte, error) {
	return []byte(a), nil
}

func (a TextAddr) Key() string {
	panic("cannot use TextAddr")
}

func (a TextAddr) UnmarshalText(data []byte) error {
	panic("cannot unmarshal into TextAddr")
}
