package mbapp

import (
	"context"
	"runtime"
	"sync/atomic"
	"time"

	"github.com/brendoncarroll/go-p2p"
	"github.com/brendoncarroll/go-p2p/s/swarmutil"
	"github.com/brendoncarroll/stdctx/logctx"
	"github.com/pkg/errors"
	"golang.org/x/exp/slog"
	"golang.org/x/sync/errgroup"
)

var disableFastPath bool

const (
	maxTimeout = (1 << 28) * time.Millisecond
	maxAskWait = 30 * time.Second
)

type Swarm[A p2p.Addr] struct {
	inner      p2p.SecureSwarm[A]
	mtu        int
	log        slog.Logger
	numWorkers int

	cf        context.CancelFunc
	fragLayer *fragLayer
	asker     *asker
	counter   uint32
	tells     *swarmutil.TellHub[A]
	asks      *swarmutil.AskHub[A]
}

func New[A p2p.Addr](x p2p.SecureSwarm[A], mtu int, opts ...Option) *Swarm[A] {
	config := swarmConfig{
		bgCtx:      context.Background(),
		numWorkers: runtime.GOMAXPROCS(0),
	}
	for _, opt := range opts {
		opt(&config)
	}
	ctx := config.bgCtx
	ctx, cf := context.WithCancel(ctx)
	s := &Swarm[A]{
		inner:      x,
		mtu:        mtu,
		numWorkers: config.numWorkers,

		cf:        cf,
		fragLayer: newFragLayer(),
		asker:     newAsker(),
		tells:     swarmutil.NewTellHub[A](),
		asks:      swarmutil.NewAskHub[A](),
	}
	go s.recvLoops(ctx, s.numWorkers)
	return s
}

func (s *Swarm[A]) Ask(ctx context.Context, resp []byte, dst A, req p2p.IOVec) (int, error) {
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

func (s *Swarm[A]) Tell(ctx context.Context, dst A, msg p2p.IOVec) error {
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

func (s *Swarm[A]) Receive(ctx context.Context, th func(p2p.Message[A])) error {
	return s.tells.Receive(ctx, th)
}

func (s *Swarm[A]) ServeAsk(ctx context.Context, fn func(context.Context, []byte, p2p.Message[A]) int) error {
	return s.asks.ServeAsk(ctx, fn)
}

func (s *Swarm[A]) Close() error {
	s.fragLayer.Close()
	s.asks.CloseWithError(p2p.ErrClosed)
	s.tells.CloseWithError(p2p.ErrClosed)
	return s.inner.Close()
}

func (s *Swarm[A]) LocalAddrs() []A {
	return s.inner.LocalAddrs()
}

func (s *Swarm[A]) PublicKey() p2p.PublicKey {
	return s.inner.PublicKey
}

func (s *Swarm[A]) LookupPublicKey(ctx context.Context, x A) (p2p.PublicKey, error) {
	return s.inner.LookupPublicKey(ctx, x)
}

func (s *Swarm[A]) MTU(ctx context.Context, target A) int {
	return s.mtu
}

func (s *Swarm[A]) MaxIncomingSize() int {
	return s.mtu
}

func (s *Swarm[A]) ParseAddr(x []byte) (A, error) {
	return s.inner.ParseAddr(x)
}

func (s *Swarm[A]) recvLoops(ctx context.Context, n int) error {
	eg := errgroup.Group{}
	for i := 0; i < n; i++ {
		eg.Go(func() error {
			return s.recvLoop(ctx)
		})
	}
	return eg.Wait()
}

func (s *Swarm[A]) recvLoop(ctx context.Context) error {
	var m p2p.Message[A]
	for {
		if err := p2p.Receive[A](ctx, s.inner, &m); err != nil {
			return err
		}
		if err := s.handleMessage(ctx, m.Src, m.Dst, m.Payload); err != nil {
			logctx.Errorf(ctx, "got %v while handling message from %v", err, m.Src)
		}
	}
}

func (s *Swarm[A]) handleMessage(ctx context.Context, src, dst A, data []byte) error {
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

func (s *Swarm[A]) handleTell(ctx context.Context, src, dst A, body []byte) error {
	return s.tells.Deliver(ctx, p2p.Message[A]{
		Src:     src,
		Dst:     dst,
		Payload: body,
	})
}

func (s *Swarm[A]) handleAskRequest(ctx context.Context, src, dst A, id GroupID, body []byte) error {
	respBuf := make([]byte, s.mtu)
	n, err := s.asks.Deliver(ctx, respBuf, p2p.Message[A]{
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

func (s *Swarm[A]) handleAskReply(ctx context.Context, src, dst A, id GroupID, errCode uint8, body []byte) error {
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

func (s *Swarm[A]) send(ctx context.Context, dst A, params sendParams) error {
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

func (s *Swarm[A]) getCounter() uint32 {
	return atomic.AddUint32(&s.counter, 1)
}

func (s *Swarm[A]) getTime() PhaseTime32 {
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
