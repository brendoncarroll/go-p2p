package sshswarm

import (
	"context"
	"log"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"

	"github.com/brendoncarroll/go-p2p"
	"github.com/brendoncarroll/go-p2p/s/swarmutil"
	"golang.org/x/crypto/ssh"
)

const MTU = 1 << 17

type (
	PrivateKey = ssh.Signer
	PublicKey  = ssh.PublicKey
)

var _ p2p.SecureSwarm[Addr, PublicKey] = &Swarm{}

type Swarm struct {
	ctx    context.Context
	pubKey ssh.PublicKey
	signer ssh.Signer
	l      net.Listener

	tellHub swarmutil.TellHub[Addr]
	askHub  swarmutil.AskHub[Addr]

	mu    sync.RWMutex
	conns map[string]*Conn
}

func New(laddr string, privateKey ssh.Signer, opts ...Option) (*Swarm, error) {
	l, err := net.Listen("tcp", laddr)
	if err != nil {
		return nil, err
	}
	ctx := context.Background()
	s := &Swarm{
		ctx:    ctx,
		pubKey: privateKey.PublicKey(),
		signer: privateKey,
		l:      l,

		tellHub: swarmutil.NewTellHub[Addr](),
		askHub:  swarmutil.NewAskHub[Addr](),

		conns: map[string]*Conn{},
	}

	go s.serveLoop(ctx)

	return s, nil
}

func (s *Swarm) MTU() int {
	return MTU
}

func (s *Swarm) LocalAddrs() []Addr {
	pubKey := s.signer.PublicKey()
	laddr := s.l.Addr().(*net.TCPAddr)
	ip, ok := netip.AddrFromSlice(laddr.IP)
	if !ok {
		panic(laddr)
	}
	x := Addr{
		Fingerprint: ssh.FingerprintSHA256(pubKey),
		IP:          ip,
		Port:        uint16(laddr.Port),
	}
	ys := p2p.ExpandUnspecifiedIPs([]Addr{x})
	return ys
}

func (s *Swarm) Close() error {
	s.tellHub.CloseWithError(p2p.ErrClosed)
	s.askHub.CloseWithError(p2p.ErrClosed)
	return s.l.Close()
}

func (s *Swarm) PublicKey() PublicKey {
	return s.pubKey
}

func (s *Swarm) LookupPublicKey(ctx context.Context, x Addr) (PublicKey, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	c := s.conns[x.Key()]
	if c == nil {
		return nil, p2p.ErrPublicKeyNotFound
	}
	return c.pubKey.(PublicKey), nil
}

func (s *Swarm) ServeAsk(ctx context.Context, fn func(context.Context, []byte, p2p.Message[Addr]) int) error {
	return s.askHub.ServeAsk(ctx, fn)
}

func (s *Swarm) Receive(ctx context.Context, th func(p2p.Message[Addr])) error {
	return s.tellHub.Receive(ctx, th)
}

func (s *Swarm) Ask(ctx context.Context, resp []byte, dst Addr, data p2p.IOVec) (int, error) {
	if p2p.VecSize(data) > MTU {
		return 0, p2p.ErrMTUExceeded
	}
	c, err := s.getConn(ctx, dst)
	if err != nil {
		return 0, err
	}
	reply, err := c.Send(true, p2p.VecBytes(nil, data))
	if err != nil {
		return 0, err
	}
	return copy(resp, reply), nil
}

func (s *Swarm) Tell(ctx context.Context, dst Addr, data p2p.IOVec) error {
	if p2p.VecSize(data) > MTU {
		return p2p.ErrMTUExceeded
	}
	c, err := s.getConn(ctx, dst)
	if err != nil {
		return err
	}
	_, err = c.Send(false, p2p.VecBytes(nil, data))
	if err != nil {
		return err
	}
	return nil
}

func (s *Swarm) ParseAddr(data []byte) (Addr, error) {
	return ParseAddr(data)
}

func (s *Swarm) getConn(ctx context.Context, addr Addr) (*Conn, error) {
	s.mu.RLock()
	c, exists := s.conns[addr.Key()]
	s.mu.RUnlock()
	if exists {
		return c, nil
	}

	// try to dial
	raddr := addr.IP.String() + ":" + strconv.Itoa(int(addr.Port))
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
	remoteAddr := c.RemoteAddr()
	c2, exists := s.conns[remoteAddr.Key()]
	if exists {
		return c2, nil
	}
	s.conns[remoteAddr.Key()] = c
	go c.loop(s.ctx)

	return c, nil
}

func (s *Swarm) serveLoop(ctx context.Context) {
	for {
		conn, err := s.l.Accept()
		if err != nil {
			if strings.Contains(err.Error(), "use of closed network connection") {
				err = nil
			}
			return
		}
		go func() {
			c, err := newServer(s, conn)
			if err != nil {
				log.Println("ERROR:", err)
				return
			}
			s.addConn(c)
			go c.loop(ctx)
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
