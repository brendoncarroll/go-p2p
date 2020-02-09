package sshswarm

import (
	"bytes"
	"errors"
	"fmt"
	"log"
	"net"
	"regexp"
	"strconv"

	"github.com/brendoncarroll/go-p2p"
	"golang.org/x/crypto/ssh"
)

var _ interface {
	p2p.Addr
	p2p.HasIP
} = &Addr{}

type Addr struct {
	Fingerprint string
	IP          net.IP
	Port        int
}

func NewAddr(publicKey p2p.PublicKey, host string, port int) *Addr {
	pubKey, err := ssh.NewPublicKey(publicKey)
	if err != nil {
		panic(err)
	}
	id := ssh.FingerprintSHA256(pubKey)
	ipAddr, err := net.ResolveIPAddr("tcp", host)
	if err != nil {
		panic(err)
	}
	return &Addr{
		Fingerprint: id,
		IP:          ipAddr.IP,
		Port:        port,
	}
}

func (a *Addr) MarshalText() ([]byte, error) {
	buf := bytes.Buffer{}
	fmt.Fprintf(&buf, "%s@%s:%d", a.Fingerprint, a.IP.String(), a.Port)
	return buf.Bytes(), nil
}

var addrRe = regexp.MustCompile(`^([A-z0-9\-_/:]+)@(.+):([0-9]+)$`)

func (s *Swarm) ParseAddr(data []byte) (p2p.Addr, error) {
	a := &Addr{}
	matches := addrRe.FindSubmatch(data)
	if len(matches) < 4 {
		log.Println(matches)
		return nil, errors.New("could not parse addr")
	}
	a.Fingerprint = string(matches[1])
	if ip := net.ParseIP(string(matches[2])); ip == nil {
		return nil, errors.New("could not parse ip")
	} else {
		a.IP = ip
	}
	if a.IP.To4() != nil {
		a.IP = a.IP.To4()
	}

	port, _ := strconv.Atoi(string(matches[3]))
	a.Port = port
	return a, nil
}

func (a Addr) String() string {
	return a.Key()
}

func (a Addr) Key() string {
	data, _ := a.MarshalText()
	return string(data)
}

func (a Addr) GetIP() net.IP {
	return a.IP
}

func (a *Addr) MapIP(x net.IP) p2p.Addr {
	a2 := *a
	a2.IP = x
	return &a2
}

func (a Addr) GetTCP() net.TCPAddr {
	return net.TCPAddr{
		IP:   a.IP,
		Port: a.Port,
	}
}

func (a *Addr) MapTCP(x net.TCPAddr) p2p.Addr {
	a2 := *a
	a2.IP = x.IP
	a2.Port = x.Port
	return &a2
}
