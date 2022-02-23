package sshswarm

import (
	"bytes"
	"fmt"
	"log"
	"net"
	"regexp"
	"strconv"

	"github.com/brendoncarroll/go-p2p"
	"github.com/pkg/errors"
	"golang.org/x/crypto/ssh"
)

type Addr struct {
	Fingerprint string
	IP          net.IP
	Port        uint16
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
		Port:        uint16(port),
	}
}

func (a Addr) MarshalText() ([]byte, error) {
	buf := bytes.Buffer{}
	fmt.Fprintf(&buf, "%s@%s:%d", a.Fingerprint, a.IP.String(), a.Port)
	return buf.Bytes(), nil
}

var addrRe = regexp.MustCompile(`^([A-z0-9\-_/:]+)@(.+):([0-9]+)$`)

func ParseAddr(data []byte) (*Addr, error) {
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
	port, err := strconv.ParseUint(string(matches[3]), 10, 16)
	if err != nil {
		return nil, errors.Wrapf(err, "sshswarm: parsing addr")
	}
	a.Port = uint16(port)
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

func (a Addr) MapIP(fn func(net.IP) net.IP) Addr {
	return Addr{
		Fingerprint: a.Fingerprint,
		IP:          fn(a.IP),
		Port:        a.Port,
	}
}

func (a Addr) GetTCP() net.TCPAddr {
	return net.TCPAddr{
		IP:   a.IP,
		Port: int(a.Port),
	}
}

func (a Addr) MapTCP(fn func(net.TCPAddr) net.TCPAddr) p2p.Addr {
	newTCP := fn(a.GetTCP())
	return Addr{
		Fingerprint: a.Fingerprint,
		IP:          newTCP.IP,
		Port:        uint16(newTCP.Port),
	}
}
