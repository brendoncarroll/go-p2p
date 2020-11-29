package dtlsswarm

import (
	"bytes"

	"github.com/brendoncarroll/go-p2p"
)

type Addr struct {
	ID p2p.PeerID
	p2p.Addr
}

func (a Addr) Key() string {
	data, err := a.MarshalText()
	if err != nil {
		panic(err)
	}
	return string(data)
}

func (a Addr) MarshalText() ([]byte, error) {
	inner, err := a.Addr.MarshalText()
	if err != nil {
		return nil, err
	}
	idBytes, err := a.ID.MarshalText()
	if err != nil {
		return nil, err
	}
	buf := bytes.Buffer{}
	buf.Write(idBytes)
	buf.WriteByte('@')
	buf.Write(inner)

	return buf.Bytes(), nil
}

func (a Addr) String() string {
	return a.Key()
}

func (a Addr) Unwrap() p2p.Addr {
	return a.Addr
}
