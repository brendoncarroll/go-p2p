package sshswarm

import (
	"bytes"
	"errors"
	"fmt"
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

var addrRe = regexp.MustCompile(`^([A-z0-9\-_]+)@(.+):([0-9]+)$`)

func (a *Addr) UnmarshalText(data []byte) error {
	matches := addrRe.FindSubmatch(data)
	if len(matches) < 3 {
		return errors.New("could not parse addr")
	}
	a.Fingerprint = string(matches[0])
	if ip := net.ParseIP(string(matches[1])); ip == nil {
		return errors.New("could not parse ip")
	} else {
		a.IP = ip
	}
	port, _ := strconv.Atoi(string(matches[2]))
	a.Port = port
	return nil
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
