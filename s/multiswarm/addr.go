package multiswarm

import (
	"bytes"
	"errors"
	"fmt"
	"regexp"

	"github.com/brendoncarroll/go-p2p"
)

type Addr struct {
	Transport string
	Addr      p2p.Addr
}

func (a Addr) String() string {
	data, _ := a.MarshalText()
	return string(data)
}

func (a Addr) Key() string {
	data, _ := a.MarshalText()
	return string(data)
}

func (a Addr) MarshalText() ([]byte, error) {
	buf := bytes.Buffer{}
	buf.WriteString("p2p-")
	buf.WriteString(a.Transport)
	buf.WriteString("://")
	data, err := a.Addr.MarshalText()
	if err != nil {
		return nil, err
	}
	buf.Write(data)
	return buf.Bytes(), nil
}

var addrRe = regexp.MustCompile(`^p2p-(.+?)://(.+)$`)

func (ms multiSwarm) ParseAddr(data []byte) (p2p.Addr, error) {
	addr := Addr{}
	groups := addrRe.FindSubmatch(data)
	if len(groups) != 3 {
		return nil, errors.New("could not unmarshal")
	}
	addr.Transport = string(groups[1])

	// transport
	tname := string(groups[1])
	inner, ok := ms[tname]
	if !ok {
		return nil, fmt.Errorf("AggSwarm does not have transport %s", tname)
	}
	addr.Transport = tname
	innerAddr, err := inner.ParseAddr(groups[2])
	if err != nil {
		return nil, err
	}
	addr.Addr = innerAddr
	return addr, nil
}
