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

type AllowFunc = func(p2p.PeerID) bool

func AllowAll(p2p.PeerID) bool {
	return true
}

var _ interface {
	p2p.Swarm
	p2p.Secure
	p2p.Asker
} = &Swarm{}

const MTU = 1 << 20

type Swarm struct {
	pubKey p2p.PublicKey
	signer ssh.Signer
	l      net.Listener
	af     AllowFunc

	handleAsk  p2p.AskHandler
	handleTell p2p.TellHandler

	mu    sync.RWMutex
	conns map[string]*Conn
}

func New(laddr string, privateKey p2p.PrivateKey, af AllowFunc) (*Swarm, error) {
	signer, err := ssh.NewSignerFromSigner(privateKey)
	if err != nil {
		panic(err)
	}
	if af == nil {
		af = AllowAll
	}

	l, err := net.Listen("tcp", laddr)
	if err != nil {
		return nil, err
	}
	s := &Swarm{
		pubKey: privateKey.Public(),
		signer: signer,
		l:      l,
		af:     af,

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

func (s *Swarm) LocalAddrs() []p2p.Addr {
	pubKey := s.signer.PublicKey()
	laddr := s.l.Addr().(*net.TCPAddr)
	x := &Addr{
		Fingerprint: ssh.FingerprintSHA256(pubKey),
		IP:          laddr.IP,
		Port:        laddr.Port,
	}

	ys := p2p.ExpandUnspecifiedIPs([]p2p.Addr{x})
	return ys
}

func (s *Swarm) Close() error {
	return nil
}

func (s *Swarm) PublicKey() p2p.PublicKey {
	return s.pubKey
}

func (s *Swarm) LookupPublicKey(ctx context.Context, x p2p.Addr) (p2p.PublicKey, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	x2 := x.(*Addr)
	c := s.conns[x2.Key()]
	if c == nil {
		return nil, p2p.ErrPublicKeyNotFound
	}
	return c.pubKey.(p2p.PublicKey), nil
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

func (s *Swarm) Ask(ctx context.Context, addr p2p.Addr, data p2p.IOVec) ([]byte, error) {
	a2 := addr.(*Addr)
	c, err := s.getConn(ctx, a2)
	if err != nil {
		return nil, err
	}
	reply, err := c.Send(true, p2p.VecBytes(data))
	if err != nil {
		return nil, err
	}
	return reply, nil
}

func (s *Swarm) Tell(ctx context.Context, addr p2p.Addr, data p2p.IOVec) error {
	a2 := addr.(*Addr)
	c, err := s.getConn(ctx, a2)
	if err != nil {
		return err
	}
	_, err = c.Send(false, p2p.VecBytes(data))
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
			c, err := newServer(s, conn, s.af)
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
