package quicswarm

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"io"
	"io/ioutil"
	"net"
	"strings"
	"sync"

	"github.com/brendoncarroll/go-p2p"
	"github.com/brendoncarroll/go-p2p/s/swarmutil"
	"github.com/lucas-clemente/quic-go"
	"github.com/sirupsen/logrus"
	"golang.org/x/sync/errgroup"
)

const DefaultMTU = 1 << 20

var log = p2p.Logger

var _ p2p.SecureAskSwarm = &Swarm{}

type Swarm struct {
	mtu     int
	privKey p2p.PrivateKey
	udpConn *net.UDPConn
	l       quic.Listener
	cf      context.CancelFunc

	mu        sync.Mutex
	sessCache map[sessionKey]quic.Session

	onAsk  p2p.AskHandler
	onTell p2p.TellHandler
}

func New(laddr string, privKey p2p.PrivateKey) (*Swarm, error) {
	tlsConfig := generateServerTLS(privKey)
	udpAddr, err := net.ResolveUDPAddr("udp", laddr)
	if err != nil {
		return nil, err
	}
	udpConn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		return nil, err
	}
	l, err := quic.Listen(udpConn, tlsConfig, generateQUICConfig())
	if err != nil {
		return nil, err
	}
	ctx, cf := context.WithCancel(context.Background())
	s := &Swarm{
		mtu:     DefaultMTU,
		udpConn: udpConn,
		l:       l,
		privKey: privKey,
		cf:      cf,

		sessCache: map[sessionKey]quic.Session{},

		onAsk:  p2p.NoOpAskHandler,
		onTell: p2p.NoOpTellHandler,
	}
	go s.serve(ctx)
	return s, nil
}

func (s *Swarm) OnTell(fn p2p.TellHandler) {
	if fn == nil {
		fn = p2p.NoOpTellHandler
	}
	swarmutil.AtomicSetTH(&s.onTell, fn)
}

func (s *Swarm) OnAsk(fn p2p.AskHandler) {
	if fn == nil {
		fn = p2p.NoOpAskHandler
	}
	swarmutil.AtomicSetAH(&s.onAsk, fn)
}

func (s *Swarm) Tell(ctx context.Context, addr p2p.Addr, data []byte) error {
	dst := addr.(*Addr)
	if len(data) > s.mtu {
		return p2p.ErrMTUExceeded
	}
	err := s.withSession(ctx, dst, func(sess quic.Session) error {
		// stream
		stream, err := sess.OpenUniStreamSync(ctx)
		if err != nil {
			return err
		}
		defer stream.Close()
		if deadline, yes := ctx.Deadline(); yes {
			if err := stream.SetWriteDeadline(deadline); err != nil {
				return err
			}
		}
		_, err = stream.Write(data)
		return err
	})
	if isSessionReplaced(err) {
		return s.Tell(ctx, addr, data)
	}
	return err
}

func (s *Swarm) Ask(ctx context.Context, addr p2p.Addr, data []byte) ([]byte, error) {
	dst := addr.(*Addr)
	if len(data) > s.mtu {
		return nil, p2p.ErrMTUExceeded
	}
	log := log.WithFields(logrus.Fields{
		"remote_addr": dst,
	})
	var respData []byte
	if err := s.withSession(ctx, dst, func(sess quic.Session) error {
		// stream
		stream, err := sess.OpenStreamSync(ctx)
		if err != nil {
			return err
		}
		defer stream.Close()

		log.Debugf("opened bidi-stream %d", stream.StreamID())
		// deadlines
		if deadline, yes := ctx.Deadline(); yes {
			if err := stream.SetWriteDeadline(deadline); err != nil {
				return err
			}
			if err := stream.SetReadDeadline(deadline); err != nil {
				return err
			}
		}
		// write
		if err := writeFrame(stream, data); err != nil {
			return err
		}
		log.Debug("ask request sent")
		data, err := readFrame(stream, s.mtu)
		if err != nil {
			return err
		}
		respData = data
		return nil
	}); err != nil {
		return nil, err
	}
	return respData, nil
}

func (s *Swarm) Close() (retErr error) {
	s.OnAsk(nil)
	s.OnTell(nil)
	s.cf()
	if err := s.l.Close(); retErr == nil {
		retErr = err
	}
	if err := s.udpConn.Close(); retErr == nil {
		retErr = err
	}
	return retErr
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

func (s *Swarm) LookupPublicKey(ctx context.Context, x p2p.Addr) (p2p.PublicKey, error) {
	a := x.(*Addr)
	var pubKey p2p.PublicKey
	if err := s.withSession(ctx, a, func(sess quic.Session) error {
		tlsState := sess.ConnectionState()
		// ok to panic here on OOB, it is a bug to have a session with
		// no certificates in the cache.
		cert := tlsState.PeerCertificates[0]
		pubKey = cert.PublicKey
		return nil
	}); err != nil {
		return nil, err
	}
	return pubKey, nil
}

func (s *Swarm) withSession(ctx context.Context, dst *Addr, fn func(sess quic.Session) error) error {
	s.mu.Lock()
	sess, exists := s.sessCache[sessionKey{addr: dst.Key(), outbound: false}]
	if !exists {
		sess, exists = s.sessCache[sessionKey{addr: dst.Key(), outbound: true}]
	}
	s.mu.Unlock()
	if exists {
		return fn(sess)
	}

	raddr := net.UDPAddr{
		IP:   dst.IP,
		Port: dst.Port,
	}
	sess, err := quic.DialContext(ctx, s.udpConn, &raddr, raddr.String(), generateClientTLS(s.privKey), generateQUICConfig())
	if err != nil {
		return err
	}
	peerAddr, err := addrFromSession(sess)
	if err != nil {
		return err
	}
	if !peerAddr.Equals(dst) {
		return errors.New("wrong peer")
	}
	s.putSession(peerAddr, sess, true)
	log.WithFields(logrus.Fields{
		"remote_addr": peerAddr,
	}).Debug("session established via dial")
	go s.handleSession(context.Background(), sess, peerAddr, true)
	return fn(sess)
}

func (s *Swarm) serve(ctx context.Context) {
	for {
		sess, err := s.l.Accept(ctx)
		if err != nil {
			if err != context.Canceled {
				log.Error(err)
			}
			return
		}
		addr, err := addrFromSession(sess)
		if err != nil {
			log.Warn(err)
			continue
		}
		s.putSession(addr, sess, false)
		log.WithFields(logrus.Fields{
			"remote_addr": addr,
		}).Debug("session established via listen")
		go s.handleSession(ctx, sess, addr, false)
	}
}

func (s *Swarm) handleSession(ctx context.Context, sess quic.Session, addr *Addr, isClient bool) {
	defer func() {
		s.mu.Lock()
		delete(s.sessCache, sessionKey{addr: addr.Key(), outbound: isClient})
		s.mu.Unlock()
	}()
	group := errgroup.Group{}
	group.Go(func() error {
		return s.handleAsks(ctx, sess, addr)
	})
	group.Go(func() error {
		return s.handleTells(ctx, sess, addr)
	})
	if err := group.Wait(); quicErr(err) != nil && err != context.Canceled {
		if err := sess.CloseWithError(1, err.Error()); err != nil {
			logrus.Error(err)
		}
	}
	sess.CloseWithError(0, "")
}

func (s *Swarm) handleAsks(ctx context.Context, sess quic.Session, srcAddr *Addr) error {
	log := log.WithFields(logrus.Fields{"remote_addr": *srcAddr})
	for {
		stream, err := sess.AcceptStream(ctx)
		if err != nil {
			return err
		}
		log.Debug("accepted bidi-stream ", stream.StreamID())
		go func() {
			if err := s.handleAsk(ctx, stream, srcAddr, s.makeLocalAddr(sess.LocalAddr())); err != nil {
				log.Errorf("error handling ask: %v", err)
			}
		}()
	}
}

func (s *Swarm) handleAsk(ctx context.Context, stream quic.Stream, srcAddr, dstAddr *Addr) error {
	log := log.WithFields(logrus.Fields{"remote_addr": *srcAddr})
	data, err := readFrame(stream, s.mtu)
	if err != nil {
		return err
	}
	log.Debugf("received ask request len=%d", len(data))
	m := &p2p.Message{
		Dst:     dstAddr,
		Src:     srcAddr,
		Payload: data,
	}
	respBuf := &bytes.Buffer{}
	w := &swarmutil.LimitWriter{W: respBuf, N: s.mtu}
	onAsk := swarmutil.AtomicGetAH(&s.onAsk)
	onAsk(ctx, m, w)
	if err := writeFrame(stream, respBuf.Bytes()); err != nil {
		return err
	}
	return stream.Close()
}

func (s *Swarm) handleTells(ctx context.Context, sess quic.Session, srcAddr *Addr) error {
	for {
		stream, err := sess.AcceptUniStream(ctx)
		if err != nil {
			return err
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
			onTell := swarmutil.AtomicGetTH(&s.onTell)
			onTell(m)
		}()
	}
}

func (s *Swarm) putSession(addr *Addr, newSess quic.Session, isClient bool) {
	s.mu.Lock()
	s.sessCache[sessionKey{addr: addr.Key(), outbound: isClient}] = newSess
	s.mu.Unlock()
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

func generateClientTLS(privKey p2p.PrivateKey) *tls.Config {
	cert := swarmutil.GenerateSelfSigned(privKey)

	return &tls.Config{
		Certificates:       []tls.Certificate{cert},
		InsecureSkipVerify: true,
		ClientAuth:         tls.RequireAnyClientCert,
		NextProtos:         []string{"go-p2p"},
	}
}

func generateServerTLS(privKey p2p.PrivateKey) *tls.Config {
	cert := swarmutil.GenerateSelfSigned(privKey)
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		NextProtos:   []string{"go-p2p"},
		ClientAuth:   tls.RequireAnyClientCert,
	}
}

func generateQUICConfig() *quic.Config {
	return nil
}

func writeFrame(w io.Writer, data []byte) error {
	if err := binary.Write(w, binary.BigEndian, uint32(len(data))); err != nil {
		return err
	}
	_, err := w.Write(data)
	return err
}

func readFrame(src io.Reader, maxLen int) ([]byte, error) {
	var l uint32
	binary.Read(src, binary.BigEndian, &l)
	if int(l) > maxLen {
		return nil, errors.New("frame is too big")
	}
	return ioutil.ReadAll(io.LimitReader(src, int64(l)))
}

func quicErr(err error) error {
	if strings.Contains(err.Error(), "Application error 0x0") {
		return nil
	}
	return err
}

func isSessionReplaced(err error) bool {
	if err == nil {
		return false
	}
	if strings.Contains(err.Error(), "session replaced") {
		return true
	}
	return false
}

type sessionKey struct {
	addr     string
	outbound bool
}
