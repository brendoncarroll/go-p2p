package httpswarm

import (
	"bytes"
	"context"
	"errors"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"strconv"

	"github.com/brendoncarroll/go-p2p"
)

const (
	MTU = 1 << 18
)

var (
	_   p2p.Swarm = &Swarm{}
	log           = p2p.Logger
)

type Swarm struct {
	l net.Listener
	c *http.Client
	s *http.Server

	handleTell p2p.TellHandler
}

func New(laddr string) (*Swarm, error) {
	l, err := net.Listen("tcp", laddr)
	if err != nil {
		return nil, err
	}

	s := &Swarm{
		l: l,
		c: http.DefaultClient,
		s: &http.Server{},

		handleTell: p2p.NoOpTellHandler,
	}
	s.s.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		data, err := ioutil.ReadAll(io.LimitReader(r.Body, MTU))
		if err != nil {
			log.Error(err)
			return
		}
		tcpAddr, err := parseAddr(r.RemoteAddr)
		if err != nil {
			log.Error(err)
			return
		}
		msg := p2p.Message{
			Src: Addr{
				IP:   tcpAddr.IP,
				Port: tcpAddr.Port,
			},
			Dst:     s.LocalAddrs()[0],
			Payload: data,
		}
		s.handleTell(&msg)
	})

	return s, nil
}

func (s *Swarm) Tell(ctx context.Context, addr p2p.Addr, data []byte) error {
	dst := addr.(Addr)
	u := "http://" + dst.IP.String() + ":" + strconv.Itoa(dst.Port)
	buf := bytes.NewBuffer(data)
	req, err := http.NewRequest(http.MethodPost, u, buf)
	if err != nil {
		return err
	}
	res, err := s.c.Do(req)
	if err != nil {
		return err
	}
	res.Body.Close()
	return nil
}

func (s *Swarm) OnTell(fn p2p.TellHandler) {
	s.handleTell = fn
}

func (s *Swarm) LocalAddrs() []p2p.Addr {
	tcpAddr := s.l.Addr().(*net.TCPAddr)
	return []p2p.Addr{
		Addr{
			IP:   tcpAddr.IP,
			Port: tcpAddr.Port,
		},
	}
}

func (s *Swarm) ParseAddr(data []byte) (p2p.Addr, error) {
	tcpAddr, err := parseAddr(string(data))
	if err != nil {
		return nil, err
	}
	ip := tcpAddr.IP
	if ip.To4() != nil {
		ip = ip.To4()
	}

	return Addr{
		IP:   ip,
		Port: tcpAddr.Port,
	}, nil
}

func (s *Swarm) MTU(ctx context.Context, addr p2p.Addr) int {
	return MTU
}

func (s *Swarm) Close() error {
	s.handleTell = p2p.NoOpTellHandler
	return s.l.Close()
}

func parseAddr(x string) (*net.TCPAddr, error) {
	host, port, err := net.SplitHostPort(x)
	if err != nil {
		return nil, err
	}
	ip := net.ParseIP(host)
	if len(ip) != 4 && len(ip) != 16 {
		return nil, errors.New("invalid IP")
	}
	portInt, err := strconv.Atoi(port)
	if err != nil {
		return nil, err
	}
	return &net.TCPAddr{
		IP:   ip,
		Port: portInt,
	}, nil
}
