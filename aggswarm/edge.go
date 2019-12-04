package aggswarm

import (
	"bytes"
	"errors"
	"reflect"
	"regexp"

	"github.com/brendoncarroll/go-p2p"
)

type PeerID = p2p.PeerID

// Edge implments p2p.Edge
// it represents one connection the aggregating swarm has seen.
// Index is relative to a specific instance and is not serialized.
type Edge struct {
	PeerID p2p.PeerID
	Index  int

	Transport string
	Addr      p2p.Addr
}

func (e Edge) Key() string {
	x, _ := e.Addr.MarshalText()
	return e.Transport + ":" + string(x)
}

func (e *Edge) MarshalText() ([]byte, error) {
	buf := bytes.Buffer{}
	// peer id
	data, err := e.PeerID.MarshalText()
	if err != nil {
		return nil, err
	}
	buf.Write(data)
	buf.WriteString("@")
	// transport
	buf.WriteString(e.Transport)
	buf.WriteString(":")
	data, err = e.Addr.MarshalText()
	if err != nil {
		return nil, err
	}
	buf.Write(data)
	return buf.Bytes(), nil
}

var addrRe = regexp.MustCompile(`^(.+?)@(.+?):(.+)$`)

func (e *Edge) UnmarshalText(data []byte) error {
	groups := addrRe.FindSubmatch(data)
	if len(groups) != 3 {
		return errors.New("could not unmarshal")
	}
	if err := e.PeerID.UnmarshalText(groups[0]); err != nil {
		return err
	}
	e.Transport = string(groups[1])
	e.Addr = p2p.TextAddr(groups[2])
	return nil
}

func (e *Edge) fixAddr(s *Swarm) error {
	ta, ok := e.Addr.(p2p.TextAddr)
	if !ok {
		return nil
	}
	t, exists := s.transports[e.Transport]
	if !exists {
		return errors.New("swarm doesn't have that transport")
	}
	a := t.LocalAddr()
	rv := reflect.New(reflect.TypeOf(a))
	x := rv.Interface().(p2p.Addr)
	if err := x.UnmarshalText([]byte(ta)); err != nil {
		return err
	}
	e.Addr = x
	return nil
}
