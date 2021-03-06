package quicswarm

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"io"
	"io/ioutil"
	"net"
	"strings"
	"sync"

	"github.com/brendoncarroll/go-p2p"
	"github.com/brendoncarroll/go-p2p/p2pconn"
	"github.com/brendoncarroll/go-p2p/s/swarmutil"
	"github.com/brendoncarroll/go-p2p/s/udpswarm"
	"github.com/lucas-clemente/quic-go"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"golang.org/x/sync/errgroup"
)

const DefaultMTU = 1 << 20

var log = p2p.Logger

var _ p2p.SecureAskSwarm = &Swarm{}

type Swarm struct {
	inner   p2p.Swarm
	mtu     int
	privKey p2p.PrivateKey
	pconn   net.PacketConn
	l       quic.Listener
	cf      context.CancelFunc

	mu        sync.RWMutex
	sessCache map[sessionKey]quic.Session

	tells *swarmutil.TellHub
	asks  *swarmutil.AskHub
}

func NewOnUDP(laddr string, privKey p2p.PrivateKey, opts ...Option) (*Swarm, error) {
	x, err := udpswarm.New(laddr)
	if err != nil {
		return nil, err
	}
	return New(x, privKey, opts...)
}

// New creates a new swarm on top of x, using privKey for authentication
func New(x p2p.Swarm, privKey p2p.PrivateKey, opts ...Option) (*Swarm, error) {
	pconn := p2pconn.NewPacketConn(x)
	tlsConfig := generateServerTLS(privKey)
	l, err := quic.Listen(pconn, tlsConfig, generateQUICConfig())
	if err != nil {
		return nil, err
	}
	ctx, cf := context.WithCancel(context.Background())
	s := &Swarm{
		inner:   x,
		mtu:     DefaultMTU,
		pconn:   pconn,
		l:       l,
		privKey: privKey,
		cf:      cf,

		sessCache: map[sessionKey]quic.Session{},
		tells:     swarmutil.NewTellHub(),
		asks:      swarmutil.NewAskHub(),
	}
	for _, opt := range opts {
		opt(s)
	}
	go s.serve(ctx)
	return s, nil
}

func (s *Swarm) Tell(ctx context.Context, addr p2p.Addr, data p2p.IOVec) error {
	dst := addr.(Addr)
	if len(data) > s.mtu {
		return p2p.ErrMTUExceeded
	}
	err := s.withSession(ctx, dst, func(sess quic.Session) error {
		stream, err := sess.OpenUniStream()
		if err != nil {
			return err
		}
		defer stream.Close()
		if deadline, yes := ctx.Deadline(); yes {
			if err := stream.SetWriteDeadline(deadline); err != nil {
				return err
			}
		}
		_, err = data.WriteTo(stream)
		return err
	})
	if isSessionReplaced(err) {
		return s.Tell(ctx, addr, data)
	}
	return err
}

func (s *Swarm) Recv(ctx context.Context, src, dst *p2p.Addr, buf []byte) (int, error) {
	return s.tells.Recv(ctx, src, dst, buf)
}

func (s *Swarm) Ask(ctx context.Context, resp []byte, addr p2p.Addr, data p2p.IOVec) (int, error) {
	dst := addr.(Addr)
	if len(data) > s.mtu {
		return 0, p2p.ErrMTUExceeded
	}
	log := log.WithFields(logrus.Fields{
		"remote_addr": dst,
	})
	var n int
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
		n, err = readFrame(stream, resp, s.mtu)
		return err
	}); err != nil {
		return 0, err
	}
	return n, nil
}

func (s *Swarm) ServeAsk(ctx context.Context, fn p2p.AskHandler) error {
	return s.asks.ServeAsk(ctx, fn)
}

func (s *Swarm) Close() (retErr error) {
	s.tells.CloseWithError(p2p.ErrSwarmClosed)
	s.asks.CloseWithError(p2p.ErrSwarmClosed)
	// this should also close the inner swarm
	if err := s.l.Close(); retErr == nil {
		retErr = err
	}
	s.cf()
	return retErr
}

func (s *Swarm) LocalAddrs() (ret []p2p.Addr) {
	for _, addr := range s.inner.LocalAddrs() {
		ret = append(ret, Addr{
			ID:   s.LocalID(),
			Addr: addr,
		})
	}
	return ret
}

func (s *Swarm) LocalID() p2p.PeerID {
	return p2p.NewPeerID(s.privKey.Public())
}

func (s *Swarm) MTU(context.Context, p2p.Addr) int {
	return s.mtu
}

func (s *Swarm) MaxIncomingSize() int {
	return s.mtu
}

func (s *Swarm) PublicKey() p2p.PublicKey {
	return s.privKey.Public()
}

func (s *Swarm) LookupPublicKey(ctx context.Context, x p2p.Addr) (p2p.PublicKey, error) {
	a := x.(Addr)
	var pubKey p2p.PublicKey
	if err := s.withSession(ctx, a, func(sess quic.Session) error {
		tlsState := sess.ConnectionState().TLS
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

func (s *Swarm) withSession(ctx context.Context, dst Addr, fn func(sess quic.Session) error) error {
	s.mu.Lock()
	sess, exists := s.sessCache[sessionKey{addr: dst.Key(), outbound: false}]
	if !exists {
		sess, exists = s.sessCache[sessionKey{addr: dst.Key(), outbound: true}]
	}
	s.mu.Unlock()
	if exists {
		return fn(sess)
	}

	raddr := p2pconn.NewAddr(s.inner, dst.Addr)
	host := ""
	sess, err := quic.DialContext(ctx, s.pconn, raddr, host, generateClientTLS(s.privKey), generateQUICConfig())
	if err != nil {
		return err
	}
	peerAddr, err := remoteAddrFromSession(sess)
	if err != nil {
		return err
	}
	if !peerAddr.ID.Equals(dst.ID) {
		return errors.Errorf("wrong peer HAVE: %v WANT: %v", peerAddr.ID, dst.ID)
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
		addr, err := remoteAddrFromSession(sess)
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

func (s *Swarm) handleSession(ctx context.Context, sess quic.Session, src Addr, isClient bool) {
	defer func() {
		s.mu.Lock()
		delete(s.sessCache, sessionKey{addr: src.Key(), outbound: isClient})
		s.mu.Unlock()
	}()
	eg := errgroup.Group{}
	eg.Go(func() error {
		return s.handleAsks(ctx, sess, src)
	})
	eg.Go(func() error {
		return s.handleTells(ctx, sess, src)
	})
	if err := eg.Wait(); quicErr(err) != nil && err != context.Canceled {
		if err := sess.CloseWithError(1, err.Error()); err != nil {
			logrus.Error(err)
		}
	}
	sess.CloseWithError(0, "")
}

func (s *Swarm) handleAsks(ctx context.Context, sess quic.Session, srcAddr Addr) error {
	log := log.WithFields(logrus.Fields{"remote_addr": srcAddr})
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

func (s *Swarm) handleAsk(ctx context.Context, stream quic.Stream, srcAddr, dstAddr Addr) error {
	log := log.WithFields(logrus.Fields{"remote_addr": srcAddr})
	reqData := make([]byte, s.mtu)
	n, err := readFrame(stream, reqData, s.mtu)
	if err != nil {
		return err
	}
	log.Debugf("received ask request len=%d", n)
	m := p2p.Message{
		Dst:     dstAddr,
		Src:     srcAddr,
		Payload: reqData[:n],
	}
	respBuf := make([]byte, s.mtu)
	n, err = s.asks.Deliver(ctx, respBuf, m)
	if err != nil {
		return err
	}
	if err := writeFrame(stream, p2p.IOVec{respBuf[:n]}); err != nil {
		return err
	}
	return stream.Close()
}

func (s *Swarm) handleTells(ctx context.Context, sess quic.Session, srcAddr Addr) error {
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
			m := p2p.Message{
				Dst:     s.makeLocalAddr(sess.LocalAddr()),
				Src:     srcAddr,
				Payload: data,
			}
			if err := s.tells.Deliver(ctx, m); err != nil {
				log.Errorf("during tell delivery: %v", err)
			}
		}()
	}
}

func (s *Swarm) putSession(addr Addr, newSess quic.Session, isClient bool) {
	s.mu.Lock()
	s.sessCache[sessionKey{addr: addr.Key(), outbound: isClient}] = newSess
	s.mu.Unlock()
}

// makeLocalAddr returns an Addr with the LocalID
// and the inner address from x
func (s *Swarm) makeLocalAddr(x net.Addr) Addr {
	return Addr{
		ID:   s.LocalID(),
		Addr: x.(p2pconn.Addr).Addr,
	}
}

func remoteAddrFromSession(x quic.Session) (Addr, error) {
	tlsState := x.ConnectionState().TLS
	if len(tlsState.PeerCertificates) < 1 {
		return Addr{}, errors.New("no certificates")
	}

	cert := tlsState.PeerCertificates[0]
	pubKey := cert.PublicKey
	id := p2p.NewPeerID(pubKey)

	raddr := x.RemoteAddr().(p2pconn.Addr)
	return Addr{
		ID:   id,
		Addr: raddr.Addr,
	}, nil
}

func generateClientTLS(privKey p2p.PrivateKey) *tls.Config {
	cert := swarmutil.GenerateSelfSigned(privKey)

	return &tls.Config{
		Certificates:       []tls.Certificate{cert},
		InsecureSkipVerify: true,
		ClientAuth:         tls.RequireAnyClientCert,
		NextProtos:         []string{"p2p"},
	}
}

func generateServerTLS(privKey p2p.PrivateKey) *tls.Config {
	cert := swarmutil.GenerateSelfSigned(privKey)
	localID := p2p.NewPeerID(privKey.Public())
	return &tls.Config{
		Certificates:       []tls.Certificate{cert},
		NextProtos:         []string{"p2p"},
		ClientAuth:         tls.RequireAnyClientCert,
		ServerName:         localID.String(),
		InsecureSkipVerify: true,
	}
}

func generateQUICConfig() *quic.Config {
	return &quic.Config{
		EnableDatagrams: true,
	}
}

func writeFrame(w io.Writer, data p2p.IOVec) error {
	if err := binary.Write(w, binary.BigEndian, uint32(p2p.VecSize(data))); err != nil {
		return err
	}
	_, err := data.WriteTo(w)
	return err
}

func readFrame(src io.Reader, dst []byte, maxLen int) (int, error) {
	var l uint32
	binary.Read(src, binary.BigEndian, &l)
	if int(l) > maxLen {
		return 0, errors.New("frame is too big")
	}
	if len(dst) < int(l) {
		return 0, io.ErrShortBuffer
	}
	return io.ReadFull(src, dst[:l])
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
