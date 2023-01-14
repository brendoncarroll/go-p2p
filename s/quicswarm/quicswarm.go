package quicswarm

import (
	"context"
	"crypto"
	"crypto/tls"
	"encoding/binary"
	"io"
	"net"
	"strings"
	"sync"

	"github.com/brendoncarroll/stdctx/logctx"
	"github.com/lucas-clemente/quic-go"
	"github.com/pkg/errors"
	"golang.org/x/exp/slog"
	"golang.org/x/sync/errgroup"

	"github.com/brendoncarroll/go-p2p"
	"github.com/brendoncarroll/go-p2p/f/x509"
	"github.com/brendoncarroll/go-p2p/p2pconn"
	"github.com/brendoncarroll/go-p2p/s/swarmutil"
	"github.com/brendoncarroll/go-p2p/s/udpswarm"
)

const DefaultMTU = 1 << 20

type (
	PrivateKey = x509.PrivateKey
	PublicKey  = x509.PublicKey
)

type Swarm[T p2p.Addr] struct {
	inner         p2p.Swarm[T]
	mtu           int
	registry      x509.Registry
	fingerprinter Fingerprinter
	allowFunc     func(p2p.Addr) bool
	privateKey    x509.PrivateKey
	publicKey     x509.PublicKey
	log           *slog.Logger
	pconn         net.PacketConn
	l             quic.Listener
	cf            context.CancelFunc

	mu        sync.RWMutex
	sessCache map[sessionKey]quic.Connection

	tells *swarmutil.TellHub[Addr[T]]
	asks  *swarmutil.AskHub[Addr[T]]
}

func NewOnUDP(laddr string, privKey x509.PrivateKey, opts ...Option[udpswarm.Addr]) (*Swarm[udpswarm.Addr], error) {
	x, err := udpswarm.New(laddr)
	if err != nil {
		return nil, err
	}
	return New[udpswarm.Addr](x, privKey, opts...)
}

// New creates a new swarm on top of x, using privKey for authentication
func New[T p2p.Addr](x p2p.Swarm[T], privKey x509.PrivateKey, opts ...Option[T]) (*Swarm[T], error) {
	pconn := connWrapper{p2pconn.NewPacketConn(x)}
	s := &Swarm[T]{
		inner:         x,
		mtu:           DefaultMTU,
		registry:      x509.DefaultRegistry(),
		fingerprinter: DefaultFingerprinter,
		allowFunc:     func(p2p.Addr) bool { return true },
		log:           slog.New(slog.NewTextHandler(io.Discard)),
		pconn:         pconn,
		privateKey:    privKey,

		sessCache: map[sessionKey]quic.Connection{},
		tells:     swarmutil.NewTellHub[Addr[T]](),
		asks:      swarmutil.NewAskHub[Addr[T]](),
	}
	for _, opt := range opts {
		opt(s)
	}
	pubKey, err := s.registry.PublicFromPrivate(&s.privateKey)
	if err != nil {
		return nil, err
	}
	s.publicKey = pubKey
	ctx := context.Background()
	ctx = logctx.NewContext(ctx, s.log)
	ctx, cf := context.WithCancel(ctx)
	s.cf = cf
	tlsConfig := generateServerTLS(&s.privateKey, &s.publicKey, s.fingerprinter)
	l, err := quic.Listen(pconn, tlsConfig, generateQUICConfig())
	if err != nil {
		return nil, err
	}
	s.l = l
	go s.serve(ctx)
	return s, nil
}

func (s *Swarm[T]) Tell(ctx context.Context, dst Addr[T], data p2p.IOVec) error {
	if p2p.VecSize(data) > s.mtu {
		return p2p.ErrMTUExceeded
	}
	err := s.withSession(ctx, dst, func(sess quic.Connection) error {
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
		return s.Tell(ctx, dst, data)
	}
	return err
}

func (s *Swarm[T]) Receive(ctx context.Context, th func(p2p.Message[Addr[T]])) error {
	return s.tells.Receive(ctx, th)
}

func (s *Swarm[T]) Ask(ctx context.Context, resp []byte, dst Addr[T], data p2p.IOVec) (int, error) {
	if p2p.VecSize(data) > s.mtu {
		return 0, p2p.ErrMTUExceeded
	}
	log := logctx.FromContext(ctx)
	var n int
	if err := s.withSession(ctx, dst, func(sess quic.Connection) error {
		// stream
		stream, err := sess.OpenStreamSync(ctx)
		if err != nil {
			return err
		}
		defer stream.Close()

		log.Debug("opened bidi-stream", slog.Any("stream-id", stream.StreamID()))
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

func (s *Swarm[T]) ServeAsk(ctx context.Context, fn func(context.Context, []byte, p2p.Message[Addr[T]]) int) error {
	return s.asks.ServeAsk(ctx, fn)
}

func (s *Swarm[T]) Close() (retErr error) {
	var el swarmutil.ErrList
	s.cf()
	s.tells.CloseWithError(p2p.ErrClosed)
	s.asks.CloseWithError(p2p.ErrClosed)
	el.Add(s.l.Close())
	el.Add(s.inner.Close())
	return el.Err()
}

func (s *Swarm[T]) LocalAddrs() (ret []Addr[T]) {
	for _, addr := range s.inner.LocalAddrs() {
		ret = append(ret, Addr[T]{
			ID:   s.LocalID(),
			Addr: addr,
		})
	}
	return ret
}

func (s *Swarm[T]) LocalID() p2p.PeerID {
	return s.fingerprinter(s.publicKey)
}

func (s *Swarm[T]) MTU(context.Context, Addr[T]) int {
	return s.mtu
}

func (s *Swarm[T]) MaxIncomingSize() int {
	return s.mtu
}

func (s *Swarm[T]) PublicKey() PublicKey {
	return s.publicKey
}

func (s *Swarm[T]) LookupPublicKey(ctx context.Context, x Addr[T]) (PublicKey, error) {
	var pubKey PublicKey
	if err := s.withSession(ctx, x, func(sess quic.Connection) error {
		tlsState := sess.ConnectionState().TLS
		// ok to panic here on OOB, it is a bug to have a session with
		// no certificates in the cache.
		cert := tlsState.PeerCertificates[0]
		var err error
		pubKey, err = x509.ParsePublicKey(cert.RawSubjectPublicKeyInfo)
		return err
	}); err != nil {
		return PublicKey{}, err
	}
	return pubKey, nil
}

func (s *Swarm[T]) ParseAddr(data []byte) (Addr[T], error) {
	return ParseAddr[T](s.inner.ParseAddr, data)
}

func (s *Swarm[T]) withSession(ctx context.Context, dst Addr[T], fn func(sess quic.Connection) error) error {
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
	signer, err := x509.ToStandardSigner(&s.privateKey)
	if err != nil {
		return err
	}
	sess, err = quic.DialContext(ctx, s.pconn, raddr, host, generateClientTLS(signer), generateQUICConfig())
	if err != nil {
		return err
	}
	peerAddr, err := s.remoteAddrFromSession(sess)
	if err != nil {
		return err
	}
	if !(peerAddr.ID == dst.ID) {
		return errors.Errorf("wrong peer HAVE: %v WANT: %v", peerAddr.ID, dst.ID)
	}
	s.putSession(peerAddr, sess, true)
	s.log.With(slog.Any("remote_addr", peerAddr)).Debug("session established via dial")
	go s.handleSession(context.Background(), sess, peerAddr, true)
	return fn(sess)
}

func (s *Swarm[T]) serve(ctx context.Context) {
	for {
		sess, err := s.l.Accept(ctx)
		if err != nil {
			if err != context.Canceled {
				logctx.Errorln(ctx, err)
			}
			return
		}
		addr, err := s.remoteAddrFromSession(sess)
		if err != nil {
			logctx.Warnln(ctx, err)
			continue
		}
		if !s.allowFunc(addr) {
			continue
		}
		s.putSession(addr, sess, false)
		s.log.With(slog.Any("remote_addr", addr)).Debug("session established via listen")
		go s.handleSession(ctx, sess, addr, false)
	}
}

func (s *Swarm[T]) handleSession(ctx context.Context, sess quic.Connection, src Addr[T], isClient bool) {
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
			logctx.Errorln(ctx, err)
		}
	}
	sess.CloseWithError(0, "")
}

func (s *Swarm[T]) handleAsks(ctx context.Context, sess quic.Connection, srcAddr Addr[T]) error {
	log := s.log.With(slog.Any("remote_addr", srcAddr))
	for {
		stream, err := sess.AcceptStream(ctx)
		if err != nil {
			return err
		}
		log.Debug("accepted bidi-stream ", stream.StreamID())
		go func() {
			if err := s.handleAsk(ctx, stream, srcAddr, s.makeLocalAddr(sess.LocalAddr())); err != nil {
				log.Error("error handling ask", err)
			}
		}()
	}
}

func (s *Swarm[T]) handleAsk(ctx context.Context, stream quic.Stream, srcAddr, dstAddr Addr[T]) error {
	log := s.log.With(slog.Any("remote_addr", srcAddr))
	reqData := make([]byte, s.mtu)
	n, err := readFrame(stream, reqData, s.mtu)
	if err != nil {
		return err
	}
	log.Debug("received ask request", slog.Int("len", n))
	m := p2p.Message[Addr[T]]{
		Dst:     dstAddr,
		Src:     srcAddr,
		Payload: reqData[:n],
	}
	respBuf := make([]byte, s.mtu)
	n, err = s.asks.Deliver(ctx, respBuf, m)
	if err != nil {
		return err
	}
	if n < 0 {
		return stream.Close()
	}
	if err := writeFrame(stream, p2p.IOVec{respBuf[:n]}); err != nil {
		return err
	}
	return stream.Close()
}

func (s *Swarm[T]) handleTells(ctx context.Context, sess quic.Connection, srcAddr Addr[T]) error {
	for {
		stream, err := sess.AcceptUniStream(ctx)
		if err != nil {
			return err
		}
		go func() {
			lr := io.LimitReader(stream, int64(s.mtu))
			data, err := io.ReadAll(lr)
			if err != nil {
				logctx.Errorln(ctx, err)
				return
			}
			m := p2p.Message[Addr[T]]{
				Dst:     s.makeLocalAddr(sess.LocalAddr()),
				Src:     srcAddr,
				Payload: data,
			}
			if err := s.tells.Deliver(ctx, m); err != nil {
				logctx.Errorf(ctx, "during tell delivery: %v", err)
			}
		}()
	}
}

func (s *Swarm[T]) putSession(addr Addr[T], newSess quic.Connection, isClient bool) {
	s.mu.Lock()
	s.sessCache[sessionKey{addr: addr.Key(), outbound: isClient}] = newSess
	s.mu.Unlock()
}

// makeLocalAddr returns an Addr with the LocalID
// and the inner address from x
func (s *Swarm[T]) makeLocalAddr(x net.Addr) Addr[T] {
	return Addr[T]{
		ID:   s.LocalID(),
		Addr: x.(p2pconn.Addr[T]).Addr,
	}
}

func (s *Swarm[T]) remoteAddrFromSession(x quic.Connection) (Addr[T], error) {
	tlsState := x.ConnectionState().TLS
	if len(tlsState.PeerCertificates) < 1 {
		return Addr[T]{}, errors.New("no certificates")
	}
	cert := tlsState.PeerCertificates[0]
	pubKey, err := x509.ParsePublicKey(cert.RawSubjectPublicKeyInfo)
	if err != nil {
		return Addr[T]{}, err
	}
	id := s.fingerprinter(pubKey)

	raddr := x.RemoteAddr().(p2pconn.Addr[T])
	return Addr[T]{
		ID:   id,
		Addr: raddr.Addr,
	}, nil
}

func generateClientTLS(privKey crypto.Signer) *tls.Config {
	cert := swarmutil.GenerateSelfSigned(privKey)

	return &tls.Config{
		Certificates:       []tls.Certificate{cert},
		InsecureSkipVerify: true,
		ClientAuth:         tls.RequireAnyClientCert,
		NextProtos:         []string{"p2p"},
	}
}

func generateServerTLS(privKey *PrivateKey, publicKey *PublicKey, fp Fingerprinter) *tls.Config {
	signer, err := x509.ToStandardSigner(privKey)
	if err != nil {
		panic(err)
	}
	cert := swarmutil.GenerateSelfSigned(signer)
	localID := fp(*publicKey)
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
	if err := binary.Read(src, binary.BigEndian, &l); err != nil {
		return 0, err
	}
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
