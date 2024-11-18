package sshswarm

import (
	"bytes"
	"fmt"
	"log"
	"net"
	"net/netip"
	"regexp"
	"strconv"

	"github.com/pkg/errors"
	"go.brendoncarroll.net/p2p"
	"golang.org/x/crypto/ssh"
)

type Addr struct {
	Fingerprint string
	IP          netip.Addr
	Port        uint16
}

func NewAddr(publicKey PublicKey, host string, port int) *Addr {
	id := ssh.FingerprintSHA256(publicKey)
	ipAddr, err := net.ResolveIPAddr("tcp", host)
	if err != nil {
		panic(err)
	}
	ip, ok := netip.AddrFromSlice(ipAddr.IP)
	if !ok {
		panic(ip)
	}
	return &Addr{
		Fingerprint: id,
		IP:          ip,
		Port:        uint16(port),
	}
}

func (a Addr) MarshalText() ([]byte, error) {
	buf := bytes.Buffer{}
	fmt.Fprintf(&buf, "%s@%s:%d", a.Fingerprint, a.IP.String(), a.Port)
	return buf.Bytes(), nil
}

var addrRe = regexp.MustCompile(`^([A-z0-9\-_/:]+)@(.+):([0-9]+)$`)

func ParseAddr(data []byte) (Addr, error) {
	a := Addr{}
	matches := addrRe.FindSubmatch(data)
	if len(matches) < 4 {
		log.Println(matches)
		return Addr{}, errors.New("could not parse addr")
	}
	a.Fingerprint = string(matches[1])
	ip, err := netip.ParseAddr(string(matches[2]))
	if err != nil {
		return Addr{}, errors.Wrapf(err, "parsing ip")
	}
	a.IP = ip
	port, err := strconv.ParseUint(string(matches[3]), 10, 16)
	if err != nil {
		return Addr{}, errors.Wrapf(err, "sshswarm: parsing addr")
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

func (a Addr) GetIP() netip.Addr {
	return a.IP
}

func (a Addr) MapIP(fn func(netip.Addr) netip.Addr) Addr {
	return Addr{
		Fingerprint: a.Fingerprint,
		IP:          fn(a.IP),
		Port:        a.Port,
	}
}

func (a Addr) GetTCP() net.TCPAddr {
	return net.TCPAddr{
		IP:   a.IP.AsSlice(),
		Port: int(a.Port),
	}
}

func (a Addr) MapTCP(fn func(net.TCPAddr) net.TCPAddr) p2p.Addr {
	newTCP := fn(a.GetTCP())
	ip, ok := netip.AddrFromSlice(newTCP.IP)
	if !ok {
		panic(ip)
	}
	return Addr{
		Fingerprint: a.Fingerprint,
		IP:          ip,
		Port:        uint16(newTCP.Port),
	}
}
