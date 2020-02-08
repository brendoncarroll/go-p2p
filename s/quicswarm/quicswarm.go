package quicswarm

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"errors"
	"io"
	"io/ioutil"
	"math/big"
	"net"
	"strconv"
	"sync"
	"time"

	"github.com/brendoncarroll/go-p2p"
	"github.com/brendoncarroll/go-p2p/s/swarmutil"
	"github.com/lucas-clemente/quic-go"
	"github.com/sirupsen/logrus"
)

const DefaultMTU = 1 << 20

var log = p2p.Logger

var _ p2p.SecureAskSwarm = &Swarm{}

type Swarm struct {
	mtu       int
	privKey   p2p.PrivateKey
	l         quic.Listener
	sessCache sync.Map

	onAsk  p2p.AskHandler
	onTell p2p.TellHandler
}

func New(laddr string, privKey p2p.PrivateKey) (*Swarm, error) {
	tlsConfig := generateServerTLS(privKey)
	l, err := quic.ListenAddr(laddr, tlsConfig, generateQUICConfig())
	if err != nil {
		return nil, err
	}
	s := &Swarm{
		mtu:     DefaultMTU,
		l:       l,
		privKey: privKey,
		onAsk:   p2p.NoOpAskHandler,
		onTell:  p2p.NoOpTellHandler,
	}
	go s.serve(context.Background())
	return s, nil
}

func (s *Swarm) OnTell(fn p2p.TellHandler) {
	s.onTell = fn
}

func (s *Swarm) OnAsk(fn p2p.AskHandler) {
	s.onAsk = fn
}

func (s *Swarm) Tell(ctx context.Context, addr p2p.Addr, data []byte) error {
	dst := addr.(*Addr)
	if len(data) > s.mtu {
		return p2p.ErrMTUExceeded
	}

	// session
	sess, err := s.openSession(ctx, dst)
	if err != nil {
		return err
	}

	// stream
	stream, err := sess.OpenUniStreamSync(ctx)
	if err != nil {
		return err
	}
	defer stream.Close()
	deadline, _ := ctx.Deadline()
	if err := stream.SetWriteDeadline(deadline); err != nil {
		return err
	}

	_, err = stream.Write(data)
	return err
}

func (s *Swarm) Ask(ctx context.Context, addr p2p.Addr, data []byte) ([]byte, error) {
	dst := addr.(*Addr)
	if len(data) > s.mtu {
		return nil, p2p.ErrMTUExceeded
	}

	// session
	sess, err := s.openSession(ctx, dst)
	if err != nil {
		return nil, err
	}

	// stream
	stream, err := sess.OpenStreamSync(ctx)
	if err != nil {
		return nil, err
	}
	defer stream.Close()

	deadline, _ := ctx.Deadline()
	if err := stream.SetWriteDeadline(deadline); err != nil {
		return nil, err
	}
	if err := stream.SetReadDeadline(deadline); err != nil {
		return nil, err
	}

	// write
	_, err = stream.Write(data)
	if err != nil {
		return nil, err
	}

	// read
	lr := io.LimitReader(stream, int64(s.mtu))
	return ioutil.ReadAll(lr)
}

func (s *Swarm) Close() error {
	s.onAsk = p2p.NoOpAskHandler
	s.onTell = p2p.NoOpTellHandler
	return nil
}

func (s *Swarm) LocalAddrs() []p2p.Addr {
	addr := s.makeLocalAddr(s.l.Addr())
	return p2p.ExpandUnspecifiedIPs([]p2p.Addr{addr})
}

func (s *Swarm) MTU(context.Context, p2p.Addr) int {
	return s.mtu
}

func (s *Swarm) PublicKey() p2p.PublicKey {
	return s.privKey.Public()
}

func (s *Swarm) LookupPublicKey(x p2p.Addr) p2p.PublicKey {
	a := x.(*Addr)
	sess := s.getSession(a)
	if sess == nil {
		return nil
	}
	tlsState := sess.ConnectionState()
	// ok to panic here on OOB, it is a bug to have a session with
	// no certificates in the cache.
	cert := tlsState.PeerCertificates[0]
	return cert.PublicKey
}

func (s *Swarm) openSession(ctx context.Context, dst *Addr) (sess quic.Session, err error) {
	sess = s.getSession(dst)
	if sess != nil {
		return sess, nil
	}
	raddr := dst.IP.String() + ":" + strconv.Itoa(dst.Port)
	sess, err = quic.DialAddrContext(ctx, raddr, generateClientTLS(s.privKey), generateQUICConfig())
	if err != nil {
		return nil, err
	}
	confirmAddr, err := addrFromSession(sess)
	if err != nil {
		return nil, err
	}
	if !confirmAddr.Equals(dst) {
		return nil, errors.New("wrong peer")
	}
	go s.handleSession(context.Background(), sess)
	return sess, nil
}

func (s *Swarm) serve(ctx context.Context) {
	for {
		sess, err := s.l.Accept(ctx)
		if err != nil {
			log.Error(err)
			return
		}
		go s.handleSession(ctx, sess)
	}
}

func (s *Swarm) handleSession(ctx context.Context, sess quic.Session) {
	defer sess.Close()

	addr, err := addrFromSession(sess)
	if err != nil {
		log.Warn(err)
		return
	}
	log.WithFields(logrus.Fields{
		"remote_addr": *addr,
	}).Debug("session established")

	// add session to cache
	s.putSession(addr, sess)
	defer s.deleteSession(addr)

	// run serve loops
	wg := sync.WaitGroup{}
	wg.Add(2)
	go func() {
		s.handleAsks(ctx, sess, addr)
		wg.Done()
	}()
	go func() {
		s.handleTells(ctx, sess, addr)
		wg.Done()
	}()
	wg.Wait()

}

func (s *Swarm) handleAsks(ctx context.Context, sess quic.Session, srcAddr *Addr) {
	for {
		stream, err := sess.AcceptStream(ctx)
		if err != nil {
			log.Error(err)
			sess.Close()
			return
		}

		go func() {
			lr := io.LimitReader(stream, int64(s.mtu))
			data, err := ioutil.ReadAll(lr)
			if err != nil {
				log.Error(err)
				return
			}
			m := &p2p.Message{
				Dst:     s.makeLocalAddr(sess.LocalAddr()),
				Src:     srcAddr,
				Payload: data,
			}
			buf := &bytes.Buffer{}
			w := &swarmutil.LimitWriter{W: buf, N: s.mtu}
			s.onAsk(ctx, m, w)
			if _, err := buf.WriteTo(stream); err != nil {
				log.Error(err)
			}
		}()
	}
}

func (s *Swarm) handleTells(ctx context.Context, sess quic.Session, srcAddr *Addr) {
	for {
		stream, err := sess.AcceptUniStream(ctx)
		if err != nil {
			log.Error(err)
			sess.Close()
			return
		}

		go func() {
			lr := io.LimitReader(stream, int64(s.mtu))
			data, err := ioutil.ReadAll(lr)
			if err != nil {
				log.Error(err)
				return
			}
			m := &p2p.Message{
				Dst:     s.makeLocalAddr(sess.LocalAddr()),
				Src:     srcAddr,
				Payload: data,
			}
			s.onTell(m)
		}()
	}
}

func (s *Swarm) putSession(addr *Addr, sess quic.Session) {
	s.sessCache.Store(addr.Key(), sess)
}

func (s *Swarm) getSession(addr *Addr) quic.Session {
	x, ok := s.sessCache.Load(addr.Key())
	if !ok {
		return nil
	}
	return x.(quic.Session)
}

func (s *Swarm) deleteSession(addr *Addr) {
	s.sessCache.Delete(addr.Key())
}

func (s *Swarm) makeLocalAddr(x net.Addr) *Addr {
	udpAddr := x.(*net.UDPAddr)
	addr := &Addr{
		ID:   p2p.NewPeerID(s.privKey.Public()),
		IP:   udpAddr.IP,
		Port: udpAddr.Port,
	}
	return addr
}

func addrFromSession(x quic.Session) (*Addr, error) {
	tlsState := x.ConnectionState()
	if len(tlsState.PeerCertificates) < 1 {
		return nil, errors.New("no certificates")
	}

	cert := tlsState.PeerCertificates[0]
	pubKey := cert.PublicKey
	id := p2p.NewPeerID(pubKey)

	raddr := x.RemoteAddr().(*net.UDPAddr)
	return &Addr{
		ID:   id,
		IP:   raddr.IP,
		Port: raddr.Port,
	}, nil
}

func generateSelfSigned(privKey p2p.PrivateKey) tls.Certificate {
	template := x509.Certificate{
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageClientAuth,
			x509.ExtKeyUsageServerAuth,
		},
		BasicConstraintsValid: true,
		NotBefore:             time.Now(),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		NotAfter:              time.Now().AddDate(0, 1, 0),
		SerialNumber:          big.NewInt(1),
		Version:               2,
		Subject:               pkix.Name{CommonName: hex.EncodeToString(make([]byte, 16))},
		IsCA:                  true,
	}
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, privKey.Public(), privKey)
	if err != nil {
		panic(err)
	}

	return tls.Certificate{
		Certificate: [][]byte{certDER},
		PrivateKey:  privKey,
	}
}

func generateClientTLS(privKey p2p.PrivateKey) *tls.Config {
	cert := generateSelfSigned(privKey)

	return &tls.Config{
		Certificates:       []tls.Certificate{cert},
		InsecureSkipVerify: true,
		ClientAuth:         tls.RequireAnyClientCert,
		NextProtos:         []string{"go-p2p"},
	}
}

func generateServerTLS(privKey p2p.PrivateKey) *tls.Config {
	cert := generateSelfSigned(privKey)
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		NextProtos:   []string{"go-p2p"},
		ClientAuth:   tls.RequireAnyClientCert,
	}
}

func generateQUICConfig() *quic.Config {
	return nil
}
