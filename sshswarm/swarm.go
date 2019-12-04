package sshswarm

import (
	"context"
	"log"
	"net"
	"strconv"
	"sync"

	"github.com/brendoncarroll/go-p2p"
	"golang.org/x/crypto/ssh"
)

var _ interface {
	p2p.SecureSwarm
} = &Swarm{}

const MTU = 1 << 20

type Swarm struct {
	signer ssh.Signer
	l      net.Listener

	handleAsk  p2p.AskHandler
	handleTell p2p.TellHandler

	mu    sync.RWMutex
	conns map[string]*Conn
}

func New(laddr string, privateKey p2p.PrivateKey) (*Swarm, error) {
	signer, err := ssh.NewSignerFromSigner(privateKey)
	if err != nil {
		panic(err)
	}

	l, err := net.Listen("tcp", laddr)
	if err != nil {
		return nil, err
	}
	s := &Swarm{
		signer: signer,
		l:      l,

		handleAsk:  p2p.NoOpAskHandler,
		handleTell: p2p.NoOpTellHandler,

		conns: map[string]*Conn{},
	}

	go s.serveLoop()

	return s, nil
}

func (s *Swarm) MTU(context.Context, p2p.Addr) int {
	return MTU
}

func (s *Swarm) LocalAddr() p2p.Addr {
	pubKey := s.signer.PublicKey()
	laddr := s.l.Addr().(*net.TCPAddr)
	if laddr.IP.IsUnspecified() {
		addrs, err := net.InterfaceAddrs()
		if err != nil {
			panic(err)
		}
		al := p2p.AddrList{}
		for _, addr := range addrs {
			ipNet := addr.(*net.IPNet)
			switch {
			case ipNet.IP.IsLoopback():
				continue
			case ipNet.IP.IsLinkLocalMulticast():
				continue
			case ipNet.IP.IsLinkLocalUnicast():
				continue
			default:
				a := &Addr{
					Fingerprint: ssh.FingerprintSHA256(pubKey),
					IP:          ipNet.IP,
					Port:        laddr.Port,
				}
				al = append(al, a)
			}
		}
		if len(al) == 1 {
			return al[0]
		}
		return &al
	}
	return &Addr{
		Fingerprint: ssh.FingerprintSHA256(pubKey),
		IP:          laddr.IP,
		Port:        laddr.Port,
	}
}

func (s *Swarm) Close() error {
	return nil
}

func (s *Swarm) PublicKey() p2p.PublicKey {
	return s.signer.PublicKey().(p2p.PublicKey)
}

func (s *Swarm) LookupPublicKey(x p2p.Addr) p2p.PublicKey {
	s.mu.RLock()
	defer s.mu.RUnlock()

	x2 := x.(*Addr)
	c := s.conns[x2.Key()]
	if c == nil {
		return nil
	}
	return c.pubKey.(p2p.PublicKey)
}

func (s *Swarm) OnAsk(fn p2p.AskHandler) {
	if fn == nil {
		fn = p2p.NoOpAskHandler
	}
	s.handleAsk = fn
}

func (s *Swarm) OnTell(fn p2p.TellHandler) {
	if fn == nil {
		fn = p2p.NoOpTellHandler
	}
	s.handleTell = fn
}

func (s *Swarm) Ask(ctx context.Context, addr p2p.Addr, data []byte) ([]byte, error) {
	a2 := addr.(*Addr)
	c, err := s.getConn(ctx, a2)
	if err != nil {
		return nil, err
	}
	reply, err := c.Send(true, data)
	if err != nil {
		return nil, err
	}
	return reply, nil
}

func (s *Swarm) Tell(ctx context.Context, addr p2p.Addr, data []byte) error {
	a2 := addr.(*Addr)
	c, err := s.getConn(ctx, a2)
	if err != nil {
		return err
	}
	_, err = c.Send(false, data)
	if err != nil {
		return err
	}
	return nil
}

func (s *Swarm) getConn(ctx context.Context, addr *Addr) (*Conn, error) {
	s.mu.RLock()
	c, exists := s.conns[addr.Key()]
	s.mu.RUnlock()
	if exists {
		return c, nil
	}

	// try to dial
	raddr := addr.IP.String() + ":" + strconv.Itoa(addr.Port)
	netConn, err := net.Dial("tcp", raddr)
	if err != nil {
		return nil, err
	}
	c, err = newClient(s, addr, netConn)
	if err != nil {
		return nil, err
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	remoteAddr := *c.RemoteAddr()
	c2, exists := s.conns[remoteAddr.Key()]
	if exists {
		return c2, nil
	}
	s.conns[remoteAddr.Key()] = c
	go c.loop()

	return c, nil
}

func (s *Swarm) serveLoop() {
	for {
		conn, err := s.l.Accept()
		if err != nil {
			log.Println(err)
		}
		go func() {
			c, err := newServer(s, conn)
			if err != nil {
				log.Println("ERROR:", err)
				return
			}
			s.addConn(c)
			go c.loop()
		}()
	}
}

func (s *Swarm) addConn(c *Conn) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.conns[c.RemoteAddr().Key()] = c
}

func (s *Swarm) deleteConn(c *Conn) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.conns, c.RemoteAddr().Key())
}
