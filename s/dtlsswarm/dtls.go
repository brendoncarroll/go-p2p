package dtlsswarm

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"sync"

	"github.com/brendoncarroll/go-p2p"
	"github.com/brendoncarroll/go-p2p/s/swarmutil"
	"github.com/pion/dtls/v2"
)

// DTLSOverhead is the per message overhead added by the protocol.
// It affects MTU calculations.
// https://tools.ietf.org/id/draft-mattsson-core-security-overhead-01.html
const DTLSOverhead = 29

var (
	log                 = p2p.Logger
	_   p2p.SecureSwarm = &Swarm{}
)

type Swarm struct {
	inner      p2p.Swarm
	privateKey p2p.PrivateKey

	handleTell p2p.TellHandler

	mu        sync.RWMutex
	dtlsConns map[string]*dtls.Conn
	fakeConns map[string]*swarmutil.FakeConn
}

func New(x p2p.Swarm, privateKey p2p.PrivateKey) *Swarm {
	s := &Swarm{
		inner:      x,
		privateKey: privateKey,
		handleTell: p2p.NoOpTellHandler,

		fakeConns: map[string]*swarmutil.FakeConn{},
		dtlsConns: map[string]*dtls.Conn{},
	}
	s.inner.OnTell(s.handleIncoming)
	return s
}

func (s *Swarm) Tell(ctx context.Context, addr p2p.Addr, data []byte) (err error) {
	dst := addr.(Addr)
	return s.send(ctx, dst, data)
}

func (s *Swarm) OnTell(fn p2p.TellHandler) {
	s.handleTell = fn
}

func (s *Swarm) LocalAddrs() (addrs []p2p.Addr) {
	id := p2p.NewPeerID(s.PublicKey())
	for _, x := range s.inner.LocalAddrs() {
		addrs = append(addrs, Addr{
			ID:   id,
			Addr: x,
		})
	}
	return addrs
}

func (s *Swarm) ParseAddr(data []byte) (p2p.Addr, error) {
	parts := bytes.SplitN(data, []byte("@"), 2)
	if len(parts) < 2 {
		return nil, errors.New("addr missing '@'")
	}

	var err error
	a := Addr{}
	if err := a.ID.UnmarshalText(parts[0]); err != nil {
		return nil, err
	}
	a.Addr, err = s.inner.ParseAddr(parts[1])
	if err != nil {
		return nil, err
	}
	return a, nil
}

func (s *Swarm) LookupPublicKey(addr p2p.Addr) p2p.PublicKey {
	s.mu.Lock()
	conn, exists := s.dtlsConns[addr.Key()]
	s.mu.Unlock()

	if !exists {
		return nil
	}

	publicKey, err := publicKeyFromConn(conn)
	if err != nil {
		panic(err)
	}
	return publicKey
}

func (s *Swarm) PublicKey() p2p.PublicKey {
	return s.privateKey.Public()
}

func (s *Swarm) MTU(ctx context.Context, addr p2p.Addr) int {
	dst := addr.(Addr)
	return s.inner.MTU(ctx, dst) - DTLSOverhead
}

func (s *Swarm) Close() error {
	s.handleTell = p2p.NoOpTellHandler
	return nil
}

func (s *Swarm) handleIncoming(msg *p2p.Message) {
	conn, created := s.getFakeConn(msg.Dst, msg.Src)
	if created {
		go func() {
			if err := s.serveConn(msg.Dst, msg.Src, conn); err != nil {
				log.Error(err)
			}
		}()
	}
	conn.Deliver(msg.Payload)
}

func (s *Swarm) send(ctx context.Context, dst Addr, data []byte) (err error) {
	s.mu.RLock()
	conn, exists := s.dtlsConns[dst.Key()]
	s.mu.RUnlock()

	if !exists {
		fakeConn, _ := s.getFakeConn(s.inner.LocalAddrs()[0], dst.Addr)
		conn, err = s.dialConn(dst, fakeConn)
		if err != nil {
			return err
		}
	}
	_, err = conn.Write(data)
	return err
}

func (s *Swarm) serveConn(laddr, raddr p2p.Addr, fakeConn *swarmutil.FakeConn) error {
	config := generateServerConfig(s.privateKey)
	conn, err := dtls.Server(fakeConn, config)
	if err != nil {
		return err
	}

	certs := conn.RemoteCertificate()
	if len(certs) < 1 {
		conn.Close()
		return errors.New("no cert")
	}
	cert, err := x509.ParseCertificate(certs[0])
	if err != nil {
		return err
	}

	id := p2p.NewPeerID(cert.PublicKey)
	raddr2 := Addr{
		ID:   id,
		Addr: raddr,
	}
	laddr2 := Addr{
		ID:   p2p.NewPeerID(s.PublicKey()),
		Addr: laddr,
	}

	s.mu.Lock()
	s.dtlsConns[raddr2.Key()] = conn
	s.mu.Unlock()

	return s.connLoop(laddr2, raddr2, conn)
}

func (s *Swarm) dialConn(raddr Addr, fakeConn *swarmutil.FakeConn) (*dtls.Conn, error) {
	config := generateClientConfig(s.privateKey)
	conn, err := dtls.Client(fakeConn, config)
	if err != nil {
		return nil, err
	}

	certs := conn.RemoteCertificate()
	if len(certs) < 1 {
		return nil, errors.New("no cert")
	}
	cert, err := x509.ParseCertificate(certs[0])
	if err != nil {
		return nil, err
	}

	if err := matchesAddr(raddr, cert); err != nil {
		return nil, err
	}

	s.mu.Lock()
	s.dtlsConns[raddr.Key()] = conn
	s.mu.Unlock()

	laddr := s.LocalAddrs()[0]
	go func() {
		if err := s.connLoop(laddr.(Addr), raddr, conn); err != nil {
			log.Error(err)
		}
	}()

	return conn, nil
}

func (s *Swarm) connLoop(laddr, raddr Addr, conn *dtls.Conn) error {
	defer conn.Close()
	defer s.deleteDtlsConn(raddr)
	defer s.deleteFakeConn(raddr.Addr)

	mtu := s.MTU(context.TODO(), raddr)
	buf := make([]byte, mtu)
	for {
		n, err := conn.Read(buf)
		if err != nil {
			return err
		}
		msg := &p2p.Message{
			Src:     raddr,
			Dst:     laddr,
			Payload: buf[:n],
		}
		s.handleTell(msg)
	}
}

func (s *Swarm) getFakeConn(laddr, raddr p2p.Addr) (*swarmutil.FakeConn, bool) {
	s.mu.RLock()
	conn, exists := s.fakeConns[raddr.Key()]
	s.mu.RUnlock()
	if exists {
		return conn, false
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	conn = swarmutil.NewFakeConn()
	conn.LAddr = laddr.Key()
	conn.RAddr = raddr.Key()
	conn.OnWrite = func(ctx context.Context, data []byte) error {
		return s.inner.Tell(ctx, raddr, data)
	}
	s.fakeConns[raddr.Key()] = conn

	return conn, true
}

func (s *Swarm) deleteFakeConn(raddr p2p.Addr) {
	s.mu.Lock()
	delete(s.fakeConns, raddr.Key())
	s.mu.Unlock()
}

func (s *Swarm) deleteDtlsConn(raddr Addr) {
	s.mu.Lock()
	delete(s.dtlsConns, raddr.Key())
	s.mu.Unlock()
}

func matchesAddr(addr Addr, cert *x509.Certificate) error {
	if cert == nil {
		return errors.New("no certificate")
	}
	id := p2p.NewPeerID(cert.PublicKey)
	if !addr.ID.Equals(id) {
		return fmt.Errorf("want peer %v got public key for %v", addr.ID, id)
	}
	return nil
}

func publicKeyFromConn(conn *dtls.Conn) (p2p.PublicKey, error) {
	certs := conn.RemoteCertificate()
	if len(certs) < 1 {
		return nil, errors.New("no cert")
	}
	cert, err := x509.ParseCertificate(certs[0])
	if err != nil {
		return nil, err
	}
	return cert.PublicKey, nil
}

func generateServerConfig(privKey p2p.PrivateKey) *dtls.Config {
	cert := swarmutil.GenerateSelfSigned(privKey)
	return &dtls.Config{
		Certificates:       []tls.Certificate{cert},
		InsecureSkipVerify: true,
		ClientAuth:         dtls.RequireAnyClientCert,
	}
}

func generateClientConfig(privKey p2p.PrivateKey) *dtls.Config {
	cert := swarmutil.GenerateSelfSigned(privKey)
	return &dtls.Config{
		Certificates:       []tls.Certificate{cert},
		InsecureSkipVerify: true,
		ClientAuth:         dtls.RequireAnyClientCert,
	}
}
