package multiswarm

import (
	"bytes"
	"regexp"

	"github.com/brendoncarroll/go-p2p"
	"github.com/pkg/errors"
)

var _ p2p.UnwrapAddr = Addr{}

type Addr struct {
	Transport string
	Addr      p2p.Addr
}

func (a Addr) Unwrap() p2p.Addr {
	return a.Addr
}

func (a Addr) Map(f func(p2p.Addr) p2p.Addr) p2p.Addr {
	return Addr{
		Transport: a.Transport,
		Addr:      f(a.Addr),
	}
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
	buf.WriteString(a.Transport)
	buf.WriteString("://")
	data, err := a.Addr.MarshalText()
	if err != nil {
		return nil, err
	}
	buf.Write(data)
	return buf.Bytes(), nil
}

func NewSchemaFromSwarms(sws map[string]DynSwarm) AddrSchema {
	parsers := make(map[string]parserFunc, len(sws))
	for k, sw := range sws {
		parsers[k] = sw.ParseAddr
	}
	return AddrSchema{
		parsers: parsers,
	}
}

func NewSchemaFromSecureSwarms(sws map[string]DynSecureSwarm) AddrSchema {
	sws2 := make(map[string]DynSwarm, len(sws))
	for k, v := range sws {
		sws2[k] = v
	}
	return NewSchemaFromSwarms(sws2)
}

var addrRe = regexp.MustCompile(`^(.+?)://(.+)$`)

type parserFunc = func([]byte) (*p2p.Addr, error)

// AddrSchema is an address scheme for parsing addresses from multiple swarms
type AddrSchema struct {
	parsers map[string]parserFunc
}

func (as AddrSchema) ParseAddr(x []byte) (*Addr, error) {
	groups := addrRe.FindSubmatch(x)
	if len(groups) != 3 {
		return nil, errors.New("could not unmarshal")
	}
	transport := string(groups[1])
	parser, exists := as.parsers[transport]
	if !exists {
		return nil, errors.Errorf("%v does not exist in muiltiswarm.Schema", transport)
	}
	innerAddr, err := parser(groups[2])
	if err != nil {
		return nil, err
	}
	return &Addr{
		Transport: transport,
		Addr:      *innerAddr,
	}, nil
}
