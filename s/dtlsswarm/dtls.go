package dtlsswarm

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"sync"

	"github.com/brendoncarroll/go-p2p"
	"github.com/brendoncarroll/go-p2p/s/swarmutil"
	"github.com/pion/dtls/v2"
	"github.com/sirupsen/logrus"
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

	mu                sync.RWMutex
	lowerAddr2Session map[string]*session
	upperAddr2Session map[string]*session
}

func New(x p2p.Swarm, privateKey p2p.PrivateKey) *Swarm {
	switch privateKey.(type) {
	case ed25519.PrivateKey, *ed25519.PrivateKey:
		panic("ed25519 keys not supported")
	}

	s := &Swarm{
		inner:             x,
		privateKey:        privateKey,
		handleTell:        p2p.NoOpTellHandler,
		lowerAddr2Session: map[string]*session{},
		upperAddr2Session: map[string]*session{},
	}
	s.inner.OnTell(s.fromBelow)
	return s
}

func (s *Swarm) Tell(ctx context.Context, addr p2p.Addr, data []byte) (err error) {
	dst := addr.(Addr)
	return s.tell(ctx, dst, data)
}

func (s *Swarm) OnTell(fn p2p.TellHandler) {
	swarmutil.AtomicSetTH(&s.handleTell, fn)
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
	target := addr.(Addr)
	s.mu.RLock()
	sess, exists := s.upperAddr2Session[target.Addr.Key()]
	s.mu.RUnlock()
	if !exists {
		return nil
	}
	return sess.publicKey
}

func (s *Swarm) PublicKey() p2p.PublicKey {
	return s.privateKey.Public()
}

func (s *Swarm) MTU(ctx context.Context, addr p2p.Addr) int {
	dst := addr.(Addr)
	return s.inner.MTU(ctx, dst.Addr) - DTLSOverhead
}

func (s *Swarm) Close() error {
	s.OnTell(p2p.NoOpTellHandler)
	return s.inner.Close()
}

func (s *Swarm) fromBelow(msg *p2p.Message) {
	laddr := msg.Dst
	raddr := msg.Src
	// check if session exists, create if not
	s.mu.RLock()
	sess, exists := s.lowerAddr2Session[raddr.Key()]
	s.mu.RUnlock()
	if !exists {
		s.mu.Lock()
		sess, exists = s.lowerAddr2Session[raddr.Key()]
		if !exists {
			sess = s.newSession(laddr, raddr)
			s.lowerAddr2Session[raddr.Key()] = sess
			go s.runSession(sess, false)
		}
		s.mu.Unlock()
	} else {
	}
	// now we have the session
	if err := sess.fakeConn.Deliver(msg.Payload); err != nil {
		logrus.Error(err)
		s.dropSession(sess)
		panic(err)
	}
}

func (s *Swarm) tell(ctx context.Context, dst Addr, data []byte) (err error) {
	// lower addresses
	laddr := s.inner.LocalAddrs()[0]
	raddr := dst.Addr

	s.mu.RLock()
	sess, exists := s.upperAddr2Session[dst.Key()]
	s.mu.RUnlock()
	if !exists {
		s.mu.Lock()
		sess, exists = s.upperAddr2Session[dst.Key()]
		sess2, exists2 := s.lowerAddr2Session[dst.Addr.Key()]
		if !exists && !exists2 {
			sess = s.newSession(laddr, raddr)
			sess.upperRemote = dst
			s.upperAddr2Session[dst.Key()] = sess
			s.lowerAddr2Session[raddr.Key()] = sess
			go s.runSession(sess, true)
		} else if !exists && exists2 {
			sess = sess2
		}
		s.mu.Unlock()
	}
	// now we have the session
	return sess.send(ctx, data)
}

func (s *Swarm) runSession(sess *session, isClient bool) {
	defer s.dropSession(sess)

	ctx := context.Background()
	var dconn *dtls.Conn
	if err := func() error {
		var err error
		defer close(sess.handshakeDone)
		defer func() { sess.handshakeErr = err }()

		if isClient {
			config := generateClientConfig(s.privateKey)
			dconn, err = dtls.ClientWithContext(ctx, sess.fakeConn, config)
			if err != nil {
				return err
			}
		} else {
			config := generateServerConfig(s.privateKey)
			dconn, err = dtls.ServerWithContext(ctx, sess.fakeConn, config)
			if err != nil {
				return err
			}
		}
		pubKey, err := publicKeyFromConn(dconn)
		if err != nil {
			return err
		}
		sess.conn = dconn
		sess.publicKey = pubKey
		sess.peerID = p2p.NewPeerID(pubKey)
		log.Debug("connected to", sess.peerID)
		if !isClient {
			sess.upperRemote = Addr{
				Addr: sess.lowerRemote,
				ID:   sess.peerID,
			}
			s.mu.Lock()
			s.upperAddr2Session[sess.upperRemote.Key()] = sess
			s.mu.Unlock()
		} else {
			if err := matchesAddr(sess.upperRemote, dconn); err != nil {
				return err
			}
		}
		return nil
	}(); err != nil {
		if isClient {
			log.Error("handkshake error dialing: ", err)
		} else {
			log.Error("handshake error listening: ", err)
		}
		return
	}

	// read loop
	if err := func() error {
		mtu := s.inner.MTU(context.TODO(), sess.lowerRemote)
		buf := make([]byte, mtu)
		for {
			n, err := dconn.Read(buf)
			if err != nil {
				return err
			}
			msg := &p2p.Message{
				Src:     sess.upperRemote,
				Dst:     s.LocalAddrs()[0],
				Payload: buf[:n],
			}
			handleTell := swarmutil.AtomicGetTH(&s.handleTell)
			handleTell(msg)
		}
	}(); err != nil {
		log.Error("error reading: ", err)
	}
}

func (s *Swarm) newSession(laddr, raddr p2p.Addr) *session {
	return &session{
		lowerRemote:   raddr,
		fakeConn:      s.newFakeConn(laddr, raddr),
		handshakeDone: make(chan struct{}),
	}
}

func (s *Swarm) newFakeConn(laddr, raddr p2p.Addr) *swarmutil.FakeConn {
	return swarmutil.NewFakeConn(laddr, raddr, func(ctx context.Context, data []byte) error {
		return s.inner.Tell(ctx, raddr, data)
	})
}

func (s *Swarm) dropSession(sess *session) {
	log.Debug("deleting session", sess.lowerRemote)
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.lowerAddr2Session, sess.lowerRemote.Key())
	if sess.upperRemote.Addr != nil {
		delete(s.upperAddr2Session, sess.upperRemote.Key())
	}
}

func matchesAddr(addr Addr, conn *dtls.Conn) error {
	certs := conn.ConnectionState().PeerCertificates
	if len(certs) < 1 {
		return errors.New("no certificate")
	}
	cert, err := x509.ParseCertificate(certs[0])
	if err != nil {
		return err
	}
	id := p2p.NewPeerID(cert.PublicKey)
	if !addr.ID.Equals(id) {
		return fmt.Errorf("want peer %v got public key for %v", addr.ID, id)
	}
	return nil
}

func publicKeyFromConn(conn *dtls.Conn) (p2p.PublicKey, error) {
	cstate := conn.ConnectionState()
	certs := cstate.PeerCertificates
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
		ClientAuth:         dtls.RequireAnyClientCert,
		InsecureSkipVerify: true,
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

type session struct {
	// init
	lowerRemote p2p.Addr
	fakeConn    *swarmutil.FakeConn

	// after auth
	handshakeDone chan struct{}
	handshakeErr  error
	conn          *dtls.Conn
	peerID        p2p.PeerID
	publicKey     p2p.PublicKey
	upperRemote   Addr
}

func (s *session) send(ctx context.Context, data []byte) error {
	<-s.handshakeDone
	if s.handshakeErr != nil {
		return s.handshakeErr
	}
	_, err := s.conn.Write(data)
	return err
}

func (s *session) close() error {
	return s.conn.Close()
}
