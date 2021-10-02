package mbapp

import (
	"context"
	"runtime"
	"sync/atomic"
	"time"

	"github.com/brendoncarroll/go-p2p"
	"github.com/brendoncarroll/go-p2p/s/swarmutil"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"golang.org/x/sync/errgroup"
)

var _ p2p.SecureAskSwarm = &Swarm{}
var disableFastPath bool

const (
	maxTimeout = (1 << 28) * time.Millisecond
	maxAskWait = 30 * time.Second
)

type Swarm struct {
	inner      p2p.SecureSwarm
	mtu        int
	log        *logrus.Logger
	numWorkers int

	cf        context.CancelFunc
	fragLayer *fragLayer
	asker     *asker
	counter   uint32
	tells     *swarmutil.TellHub
	asks      *swarmutil.AskHub
}

func New(x p2p.SecureSwarm, mtu int, opts ...Option) *Swarm {
	ctx, cf := context.WithCancel(context.Background())
	s := &Swarm{
		inner:      x,
		mtu:        mtu,
		log:        logrus.New(),
		numWorkers: runtime.GOMAXPROCS(0),

		cf:        cf,
		fragLayer: newFragLayer(),
		asker:     newAsker(),
		tells:     swarmutil.NewTellHub(),
		asks:      swarmutil.NewAskHub(),
	}
	s.log.SetLevel(logrus.ErrorLevel)
	for _, opt := range opts {
		opt(s)
	}
	go s.recvLoops(ctx, s.numWorkers)
	return s
}

func (s *Swarm) Ask(ctx context.Context, resp []byte, dst p2p.Addr, req p2p.IOVec) (int, error) {
	ctx, cf := context.WithTimeout(ctx, maxAskWait)
	defer cf()
	if p2p.VecSize(req) > s.mtu {
		return 0, p2p.ErrMTUExceeded
	}
	// create ask in map
	counter := s.getCounter()
	originTime := s.getTime()
	id := askID{GroupID: GroupID{Counter: counter, OriginTime: originTime}, Addr: dst.String()}
	ask := s.asker.createAsk(id, resp)
	defer s.asker.removeAsk(id)
	// call send
	if err := s.send(ctx, dst, sendParams{
		isAsk:      true,
		isReply:    false,
		counter:    counter,
		originTime: originTime,
		timeout:    getTimeoutMillis(ctx),

		m: req,
	}); err != nil {
		return 0, err
	}
	// wait or timeout
	if err := ask.await(ctx); err != nil {
		return 0, errors.Wrapf(err, "waiting for ask response from %v", dst)
	}
	if ask.errCode > 0 {
		err := AppError{
			Addr:     dst,
			Code:     ask.errCode,
			Request:  p2p.VecBytes(nil, req),
			Response: resp[:ask.n],
		}
		return 0, err
	}
	return ask.n, nil
}

func (s *Swarm) Tell(ctx context.Context, dst p2p.Addr, msg p2p.IOVec) error {
	if p2p.VecSize(msg) > s.mtu {
		return p2p.ErrMTUExceeded
	}
	return s.send(ctx, dst, sendParams{
		counter:    s.getCounter(),
		originTime: s.getTime(),
		isAsk:      false,
		isReply:    false,
		timeout:    getTimeoutMillis(ctx),
		m:          msg,
	})
}

func (s *Swarm) Receive(ctx context.Context, th p2p.TellHandler) error {
	return s.tells.Receive(ctx, th)
}

func (s *Swarm) ServeAsk(ctx context.Context, fn p2p.AskHandler) error {
	return s.asks.ServeAsk(ctx, fn)
}

func (s *Swarm) Close() error {
	s.fragLayer.Close()
	s.asks.CloseWithError(p2p.ErrClosed)
	s.tells.CloseWithError(p2p.ErrClosed)
	return s.inner.Close()
}

func (s *Swarm) LocalAddrs() []p2p.Addr {
	return s.inner.LocalAddrs()
}

func (s *Swarm) PublicKey() p2p.PublicKey {
	return s.inner.PublicKey
}

func (s *Swarm) LookupPublicKey(ctx context.Context, x p2p.Addr) (p2p.PublicKey, error) {
	return s.inner.LookupPublicKey(ctx, x)
}

func (s *Swarm) MTU(ctx context.Context, target p2p.Addr) int {
	return s.mtu
}

func (s *Swarm) MaxIncomingSize() int {
	return s.mtu
}

func (s *Swarm) ParseAddr(x []byte) (p2p.Addr, error) {
	return s.inner.ParseAddr(x)
}

func (s *Swarm) recvLoops(ctx context.Context, n int) error {
	eg := errgroup.Group{}
	for i := 0; i < n; i++ {
		eg.Go(func() error {
			return s.recvLoop(ctx)
		})
	}
	return eg.Wait()
}

func (s *Swarm) recvLoop(ctx context.Context) error {
	var m p2p.Message
	for {
		if err := p2p.Receive(ctx, s.inner, &m); err != nil {
			return err
		}
		if err := s.handleMessage(ctx, m.Src, m.Dst, m.Payload); err != nil {
			s.log.Errorf("got %v while handling message from %v", err, m.Src)
		}
	}
}

func (s *Swarm) handleMessage(ctx context.Context, src, dst p2p.Addr, data []byte) error {
	hdr, body, err := ParseMessage(data)
	if err != nil {
		return err
	}
	originTime := hdr.GetOriginTime().UTC(time.Now(), time.Millisecond)
	partCount := hdr.GetPartCount()
	totalSize := hdr.GetTotalSize()
	partIndex := hdr.GetPartIndex()
	if totalSize > uint32(s.mtu) {
		return errors.Errorf("total message size exceeds max")
	}
	gid := hdr.GroupID()
	timeout := hdr.GetTimeout()
	return s.fragLayer.handlePart(src, gid, partIndex, partCount, totalSize, body, func(buf []byte) error {
		if hdr.IsAsk() {
			ctx, cf := context.WithDeadline(ctx, originTime.Add(timeout))
			defer cf()
			if hdr.IsReply() {
				return s.handleAskReply(ctx, src, dst, gid, hdr.GetErrorCode(), buf)
			} else {
				return s.handleAskRequest(ctx, src, dst, gid, buf)
			}
		} else {
			return s.handleTell(ctx, src, dst, buf)
		}
	})
}

func (s *Swarm) handleTell(ctx context.Context, src, dst p2p.Addr, body []byte) error {
	return s.tells.Deliver(ctx, p2p.Message{
		Src:     src,
		Dst:     dst,
		Payload: body,
	})
}

func (s *Swarm) handleAskRequest(ctx context.Context, src, dst p2p.Addr, id GroupID, body []byte) error {
	respBuf := make([]byte, s.mtu)
	n, err := s.asks.Deliver(ctx, respBuf, p2p.Message{
		Src:     src,
		Dst:     dst,
		Payload: body,
	})
	if err != nil {
		return err
	}
	errCode, bufLen := extractErrorCode(n)
	return s.send(ctx, src, sendParams{
		isAsk:      true,
		isReply:    true,
		originTime: id.OriginTime,
		counter:    id.Counter,
		errCode:    errCode,
		m:          p2p.IOVec{respBuf[:bufLen]},
	})
}

func (s *Swarm) handleAskReply(ctx context.Context, src, dst p2p.Addr, id GroupID, errCode uint8, body []byte) error {
	ask := s.asker.getAndRemoveAsk(askID{
		GroupID: id,
		Addr:    src.String(),
	})
	if ask == nil {
		return errors.Errorf("got reply for non existent ask %v", id)
	}
	ask.complete(body, errCode)
	return nil
}

type sendParams struct {
	isAsk      bool
	isReply    bool
	errCode    uint8
	counter    uint32
	originTime PhaseTime32
	timeout    uint32

	m p2p.IOVec
}

func (s *Swarm) send(ctx context.Context, dst p2p.Addr, params sendParams) error {
	hdrBuf := [HeaderSize]byte{}
	hdr := Header(hdrBuf[:])
	hdr.SetIsAsk(params.isAsk)
	hdr.SetIsReply(params.isReply)
	hdr.SetErrorCode(params.errCode)
	hdr.SetCounter(params.counter)
	hdr.SetOriginTime(params.originTime)
	hdr.SetTimeout(params.timeout)

	mtu := s.inner.MTU(ctx, dst)
	partSize := (mtu - HeaderSize)
	totalSize := p2p.VecSize(params.m)
	partCount := totalSize / partSize
	if partSize*partCount < totalSize {
		partCount++
	}
	hdr.SetPartIndex(uint16(0))
	hdr.SetPartCount(uint16(partCount))
	hdr.SetTotalSize(uint32(totalSize))

	// fast path
	if partCount < 2 {
		msg := p2p.IOVec{[]byte(hdr)}
		msg = append(msg, params.m...)
		return s.inner.Tell(ctx, dst, msg)
	}

	whole := p2p.VecBytes(nil, params.m)
	eg := errgroup.Group{}
	for i := 0; i < partCount; i++ {
		hdrBuf2 := hdrBuf
		hdr := Header(hdrBuf2[:])
		hdr.SetPartIndex(uint16(i))
		start := i * partSize
		end := (i + 1) * partSize
		if end > len(whole) {
			end = len(whole)
		}
		eg.Go(func() error {
			msg := p2p.IOVec{[]byte(hdr)}
			msg = append(msg, whole[start:end])
			return s.inner.Tell(ctx, dst, msg)
		})
	}
	return eg.Wait()
}

func (s *Swarm) getCounter() uint32 {
	return atomic.AddUint32(&s.counter, 1)
}

func (s *Swarm) getTime() PhaseTime32 {
	return NewPhaseTime32(time.Now().UTC(), time.Millisecond)
}

func getTimeoutMillis(ctx context.Context) uint32 {
	deadline, ok := ctx.Deadline()
	if !ok {
		return uint32(maxTimeout.Milliseconds())
	}
	now := time.Now().UTC()
	timeout := deadline.Sub(now)
	return uint32(timeout.Milliseconds())
}

func extractErrorCode(n int) (uint8, int) {
	if n >= 0 {
		return 0, n
	}
	// TODO: allow setting of error codes
	// for now error code is constant, and n is always 0
	return 0xff, 0
}
