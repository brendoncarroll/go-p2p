package mbapp

import (
	"context"
	"sync/atomic"
	"time"

	"github.com/brendoncarroll/go-p2p"
	"github.com/brendoncarroll/go-p2p/s/swarmutil"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"golang.org/x/sync/errgroup"
)

var _ p2p.SecureAskSwarm = &Swarm{}

type Swarm struct {
	inner p2p.SecureSwarm
	mtu   int

	cf        context.CancelFunc
	fragLayer *fragLayer
	asker     *asker
	counter   uint32
	tells     *swarmutil.TellHub
	asks      *swarmutil.AskHub
}

func New(x p2p.SecureSwarm, mtu int) *Swarm {
	ctx, cf := context.WithCancel(context.Background())
	s := &Swarm{
		inner: x,
		mtu:   mtu,

		cf:        cf,
		fragLayer: newFragLayer(),
		asker:     newAsker(),
		tells:     swarmutil.NewTellHub(),
		asks:      swarmutil.NewAskHub(),
	}
	go s.recvLoop(ctx)
	return s
}

func (s *Swarm) Ask(ctx context.Context, resp []byte, dst p2p.Addr, req p2p.IOVec) (int, error) {
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
		timeout:    getTimeout(ctx),

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

		m: msg,
	})
}

func (s *Swarm) Recv(ctx context.Context, src, dst *p2p.Addr, buf []byte) (int, error) {
	return s.tells.Receive(ctx, src, dst, buf)
}

func (s *Swarm) ServeAsk(ctx context.Context, fn p2p.AskHandler) error {
	return s.asks.ServeAsk(ctx, fn)
}

func (s *Swarm) Close() error {
	s.fragLayer.Close()
	s.asks.CloseWithError(p2p.ErrSwarmClosed)
	s.tells.CloseWithError(p2p.ErrSwarmClosed)
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
	return s.inner.MaxIncomingSize()
}

func (s *Swarm) ParseAddr(x []byte) (p2p.Addr, error) {
	return s.inner.ParseAddr(x)
}

func (s *Swarm) recvLoop(ctx context.Context) error {
	buf := make([]byte, s.inner.MaxIncomingSize())
	for {
		var src, dst p2p.Addr
		n, err := s.inner.Receive(ctx, &src, &dst, buf)
		if err != nil {
			return err
		}
		if err := s.handleMessage(ctx, src, dst, buf[:n]); err != nil {
			logrus.Errorf("got %v while handling message from %v", err, src)
		}
	}
}

func (s *Swarm) handleMessage(ctx context.Context, src, dst p2p.Addr, data []byte) error {
	hdr, body, err := ParseMessage(data)
	if err != nil {
		return err
	}
	partCount := hdr.GetPartCount()
	totalSize := hdr.GetTotalSize()
	if totalSize > uint32(s.mtu) {
		return errors.Errorf("total message size exceeds max")
	}
	gid := hdr.GroupID()
	// fast path
	if partCount < 2 {
		if !hdr.IsAsk() {
			return s.handleTell(ctx, src, dst, body)
		}
		if hdr.IsReply() {
			return s.handleAskReply(ctx, src, dst, gid, hdr.GetErrorCode(), body)
		} else {
			return s.handleAskRequest(ctx, src, dst, gid, body)
		}
		panic("unreachable")
	}
	col, err := s.fragLayer.getCollector(hdr.GroupID(), hdr.IsAsk(), hdr.IsReply(), int(partCount), int(totalSize))
	if err != nil {
		return err
	}
	if err := col.addPart(int(hdr.GetPartIndex()), body); err != nil {
		return err
	}
	if !col.isComplete() {
		return nil
	}
	defer s.fragLayer.dropCollector(hdr.GroupID())
	return col.withBuffer(func([]byte) error {
		if hdr.IsAsk() {
			if hdr.IsReply() {
				return s.handleAskReply(ctx, src, dst, gid, hdr.GetErrorCode(), col.buf)
			} else {
				return s.handleAskRequest(ctx, src, dst, gid, body)
			}
		} else {
			return s.handleTell(ctx, src, dst, body)
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
		n = copy(respBuf, err.Error())
	}
	return s.send(ctx, src, sendParams{
		isAsk:      true,
		isReply:    true,
		originTime: id.OriginTime,
		counter:    id.Counter,
		m:          p2p.IOVec{respBuf[:n]},
	})
}

func (s *Swarm) handleAskReply(ctx context.Context, src, dst p2p.Addr, id GroupID, errCode uint8, body []byte) error {
	ask := s.asker.getAndRemoveAsk(askID{
		GroupID: id,
		Addr:    src.String(),
	})
	if ask != nil {
		ask.complete(body, errCode)
	}
	return nil
}

type sendParams struct {
	isAsk      bool
	isReply    bool
	counter    uint32
	originTime PhaseTime32

	timeout *time.Duration

	m p2p.IOVec
}

func (s *Swarm) send(ctx context.Context, dst p2p.Addr, params sendParams) error {
	hdrBuf := [HeaderSize]byte{}
	hdr := Header(hdrBuf[:])
	hdr.SetIsAsk(params.isAsk)
	hdr.SetIsReply(params.isReply)
	hdr.SetCounter(params.counter)
	hdr.SetOriginTime(params.originTime)
	if params.timeout != nil {
		hdr.SetTimeout(*params.timeout)
	}

	mtu := s.inner.MTU(ctx, dst)
	partSize := (mtu - HeaderSize)
	totalSize := p2p.VecSize(params.m)
	numParts := totalSize / partSize

	hdr.SetPartCount(uint16(numParts))

	// fast path
	if numParts < 2 {
		msg := p2p.IOVec{[]byte(hdr)}
		msg = append(msg, params.m...)
		return s.inner.Tell(ctx, dst, msg)
	}
	eg := errgroup.Group{}
	for i := 0; i < numParts; i++ {
		hdrBuf2 := hdrBuf
		hdr := Header(hdrBuf2[:])
		hdr.SetPartIndex(uint16(i))

		eg.Go(func() error {
			msg := p2p.IOVec{[]byte(hdr)}
			msg = append(msg, params.m...)
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

func getTimeout(ctx context.Context) *time.Duration {
	deadline, ok := ctx.Deadline()
	if !ok {
		return nil
	}
	now := time.Now().UTC()
	timeout := deadline.Sub(now)
	return &timeout
}
