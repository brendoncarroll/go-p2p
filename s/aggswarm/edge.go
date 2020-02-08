package aggswarm

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"regexp"

	"github.com/brendoncarroll/go-p2p"
)

type PeerID = p2p.PeerID

// Edge implments p2p.Addr
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
	return string(x)
}

func (e Edge) String() string {
	return e.Key()
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

func (s *Swarm) ParseAddr(data []byte) (p2p.Addr, error) {
	addr := &Edge{}
	groups := addrRe.FindSubmatch(data)
	if len(groups) != 3 {
		return nil, errors.New("could not unmarshal")
	}
	// id
	if err := addr.PeerID.UnmarshalText(groups[0]); err != nil {
		return nil, err
	}
	// transport
	tname := string(groups[1])
	inner, ok := s.transports[tname]
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

func (e *Edge) GetIP() net.IP {
	if hasIP, ok := e.Addr.(p2p.HasIP); ok {
		return hasIP.GetIP()
	}
	return nil
}
